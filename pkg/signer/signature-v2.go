/*
 * Minio Cloud Storage, (C) 2016, 2017 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package signer

import (
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Signature and API related constants.
const (
	signV2Algorithm = "AWS"
)

// AWS S3 Signature V2 calculation rule is give here:
// http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationStringToSign

// Whitelist resource list that will be used in query string for signature-V2 calculation.
// The list should be alphabetically sorted
var resourceList = []string{
	"acl",
	"delete",
	"lifecycle",
	"location",
	"logging",
	"notification",
	"partNumber",
	"policy",
	"requestPayment",
	"response-cache-control",
	"response-content-disposition",
	"response-content-encoding",
	"response-content-language",
	"response-content-type",
	"response-expires",
	"torrent",
	"uploadId",
	"uploads",
	"versionId",
	"versioning",
	"versions",
	"website",
}

// DoesPolicySignatureV2Match - Check to see if policy is signed correctly.
func DoesPolicySignatureV2Match(formValues http.Header, accessKey, secretKey string) error {
	if formValues.Get("AWSAccessKeyId") != accessKey {
		return InvalidAccessKeyID
	}
	policy := formValues.Get("Policy")
	signature := formValues.Get("Signature")
	if signature != calculateSignatureV2(policy, secretKey) {
		return SignatureDoesNotMatch
	}
	return nil
}

// Escape encodedQuery string into unescaped list of query params, returns error
// if any while unescaping the values.
func unescapeQueries(encodedQuery string) (unescapedQueries []string, err error) {
	for _, query := range strings.Split(encodedQuery, "&") {
		var unescapedQuery string
		unescapedQuery, err = url.QueryUnescape(query)
		if err != nil {
			return nil, err
		}
		unescapedQueries = append(unescapedQueries, unescapedQuery)
	}
	return unescapedQueries, nil
}

// DoesPresignV2SignatureMatch - Verify query headers with presigned signature
//     - http://docs.aws.amazon.com/AmazonS3/latest/dev/RESTAuthentication.html#RESTAuthenticationQueryStringAuth
// returns ErrNone if matches. S3 errors otherwise.
func DoesPresignV2SignatureMatch(r *http.Request, accessKey, secretKey string) error {
	// r.RequestURI will have raw encoded URI as sent by the client.
	tokens := strings.SplitN(r.RequestURI, "?", 2)
	encodedResource := tokens[0]
	encodedQuery := ""
	if len(tokens) == 2 {
		encodedQuery = tokens[1]
	}

	var (
		filteredQueries []string
		gotSignature    string
		gotAccessKey    string
		gotExpires      string
		err             error
	)

	var unescapedQueries []string
	unescapedQueries, err = unescapeQueries(encodedQuery)
	if err != nil {
		return InvalidQueryParams
	}

	// Extract the necessary values from presigned query, construct a list of new filtered queries.
	for _, query := range unescapedQueries {
		keyval := strings.SplitN(query, "=", 2)
		switch keyval[0] {
		case "AWSAccessKeyId":
			gotAccessKey = keyval[1]
		case "Signature":
			gotSignature = keyval[1]
		case "Expires":
			gotExpires = keyval[1]
		default:
			filteredQueries = append(filteredQueries, query)
		}
	}

	// Invalid values returns error.
	if gotAccessKey == "" || gotSignature == "" || gotExpires == "" {
		return InvalidQueryParams
	}

	// Validate if access key id same.
	if gotAccessKey != accessKey {
		return InvalidAccessKeyID
	}

	// Make sure the request has not expired.
	expiresInt, err := strconv.ParseInt(gotExpires, 10, 64)
	if err != nil {
		return MalformedExpires
	}

	// Check if the presigned URL has expired.
	if expiresInt < time.Now().UTC().Unix() {
		return ExpiredPresignRequest
	}

	encodedResource, err = getResource(encodedResource, r.Host, globalDomainName)
	if err != nil {
		return InvalidRequest
	}

	expectedSignature := preSignatureV2(r.Method, encodedResource, strings.Join(filteredQueries, "&"), r.Header, gotExpires, secretKey)
	if gotSignature != expectedSignature {
		return SignatureDoesNotMatch
	}

	return nil
}

// Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature;
// Signature = Base64( HMAC-SHA1( YourSecretKey, UTF-8-Encoding-Of( StringToSign ) ) );
//
// StringToSign = HTTP-Verb + "\n" +
//  	Content-Md5 + "\n" +
//  	Content-Type + "\n" +
//  	Date + "\n" +
//  	CanonicalizedProtocolHeaders +
//  	CanonicalizedResource;
//
// CanonicalizedResource = [ "/" + Bucket ] +
//  	<HTTP-Request-URI, from the protocol name up to the query string> +
//  	[ subresource, if present. For example "?acl", "?location", "?logging", or "?torrent"];
//
// CanonicalizedProtocolHeaders = <described below>

// validateV2AuthHeader -  Verify authorization header with calculated header in accordance with
//     - http://docs.aws.amazon.com/AmazonS3/latest/dev/auth-request-sig-v2.html
// returns true if matches, false otherwise. if error is not nil then it is always false
func validateV2AuthHeader(v2Auth, accessKey string) error {
	if v2Auth == "" {
		return AuthHeaderEmpty
	}
	// Verify if the header algorithm is supported or not.
	if !strings.HasPrefix(v2Auth, signV2Algorithm) {
		return SignatureVersionNotSupported
	}

	// below is V2 Signed Auth header format, splitting on `space` (after the `AWS` string).
	// Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature
	authFields := strings.Split(v2Auth, " ")
	if len(authFields) != 2 {
		return MissingFields
	}

	// Then will be splitting on ":", this will seprate `AWSAccessKeyId` and `Signature` string.
	keySignFields := strings.Split(strings.TrimSpace(authFields[1]), ":")
	if len(keySignFields) != 2 {
		return MissingFields
	}

	// Validate access key
	if keySignFields[0] != accessKey {
		return InvalidAccessKeyID
	}

	return nil
}

// DoesSignV2Match - Verify authorization header with calculated header in accordance with
// signature v2.
func DoesSignV2Match(r *http.Request, accessKey, secretKey string) error {
	v2Auth := r.Header.Get("Authorization")

	if err := validateV2AuthHeader(v2Auth, accessKey); err != nil {
		return err
	}

	// r.RequestURI will have raw encoded URI as sent by the client.
	tokens := strings.SplitN(r.RequestURI, "?", 2)
	encodedResource := tokens[0]
	encodedQuery := ""
	if len(tokens) == 2 {
		encodedQuery = tokens[1]
	}

	unescapedQueries, err := unescapeQueries(encodedQuery)
	if err != nil {
		return InvalidQueryParams
	}

	encodedResource, err = getResource(encodedResource, r.Host, globalDomainName)
	if err != nil {
		return InvalidRequest
	}

	expectedAuth := signatureV2(r.Method, encodedResource, strings.Join(unescapedQueries, "&"), r.Header, accessKey, secretKey)
	if v2Auth != expectedAuth {
		return SignatureDoesNotMatch
	}

	return nil
}

func calculateSignatureV2(stringToSign string, secret string) string {
	hm := hmac.New(sha1.New, []byte(secret))
	hm.Write([]byte(stringToSign))
	return base64.StdEncoding.EncodeToString(hm.Sum(nil))
}

// Return signature-v2 for the presigned request.
func preSignatureV2(method string, encodedResource string, encodedQuery string, headers http.Header, expires string, secretKey string) string {
	stringToSign := getStringToSignV2(method, encodedResource, encodedQuery, headers, expires)
	return calculateSignatureV2(stringToSign, secretKey)
}

// Return signature-v2 authrization header.
func signatureV2(method string, encodedResource string, encodedQuery string, headers http.Header, accessKey, secretKey string) string {
	stringToSign := getStringToSignV2(method, encodedResource, encodedQuery, headers, "")
	signature := calculateSignatureV2(stringToSign, secretKey)
	return fmt.Sprintf("%s %s:%s", signV2Algorithm, accessKey, signature)
}

// Return canonical headers.
func canonicalizedAmzHeadersV2(headers http.Header) string {
	var keys []string
	keyval := make(map[string]string)
	for key := range headers {
		lkey := strings.ToLower(key)
		if !strings.HasPrefix(lkey, "x-amz-") {
			continue
		}
		keys = append(keys, lkey)
		keyval[lkey] = strings.Join(headers[key], ",")
	}
	sort.Strings(keys)
	var canonicalHeaders []string
	for _, key := range keys {
		canonicalHeaders = append(canonicalHeaders, key+":"+keyval[key])
	}
	return strings.Join(canonicalHeaders, "\n")
}

// Return canonical resource string.
func canonicalizedResourceV2(encodedResource, encodedQuery string) string {
	queries := strings.Split(encodedQuery, "&")
	keyval := make(map[string]string)
	for _, query := range queries {
		key := query
		val := ""
		index := strings.Index(query, "=")
		if index != -1 {
			key = query[:index]
			val = query[index+1:]
		}
		keyval[key] = val
	}

	var canonicalQueries []string
	for _, key := range resourceList {
		val, ok := keyval[key]
		if !ok {
			continue
		}
		if val == "" {
			canonicalQueries = append(canonicalQueries, key)
			continue
		}
		canonicalQueries = append(canonicalQueries, key+"="+val)
	}

	// The queries will be already sorted as resourceList is sorted, if canonicalQueries
	// is empty strings.Join returns empty.
	canonicalQuery := strings.Join(canonicalQueries, "&")
	if canonicalQuery != "" {
		return encodedResource + "?" + canonicalQuery
	}
	return encodedResource
}

// Return string to sign under two different conditions.
// - if expires string is set then string to sign includes date instead of the Date header.
// - if expires string is empty then string to sign includes date header instead.
func getStringToSignV2(method string, encodedResource, encodedQuery string, headers http.Header, expires string) string {
	canonicalHeaders := canonicalizedAmzHeadersV2(headers)
	if len(canonicalHeaders) > 0 {
		canonicalHeaders += "\n"
	}

	date := expires // Date is set to expires date for presign operations.
	if date == "" {
		// If expires date is empty then request header Date is used.
		date = headers.Get("Date")
	}

	// From the Amazon docs:
	//
	// StringToSign = HTTP-Verb + "\n" +
	// 	 Content-Md5 + "\n" +
	//	 Content-Type + "\n" +
	//	 Date/Expires + "\n" +
	//	 CanonicalizedProtocolHeaders +
	//	 CanonicalizedResource;
	stringToSign := strings.Join([]string{
		method,
		headers.Get("Content-MD5"),
		headers.Get("Content-Type"),
		date,
		canonicalHeaders,
	}, "\n")

	return stringToSign + canonicalizedResourceV2(encodedResource, encodedQuery)
}
