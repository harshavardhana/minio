/*
 * Minio Cloud Storage, (C) 2015, 2016, 2017 Minio, Inc.
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

// Package signer This file implements helper functions to validate AWS
// Signature Version '4' authorization header.
//
// This package provides comprehensive helpers for following signature
// types.
// - Based on Authorization header.
// - Based on Query parameters.
// - Based on Form POST policy.
package signer

import (
	"bytes"
	"encoding/hex"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/minio/minio-go/pkg/s3utils"
	"github.com/minio/sha256-simd"
)

// AWS Signature Version '4' constants.
const (
	signV4Algorithm = "AWS4-HMAC-SHA256"
	iso8601Format   = "20060102T150405Z"
	yyyymmdd        = "20060102"
)

// getCanonicalHeaders generate a list of request headers with their values
func getCanonicalHeaders(signedHeaders http.Header) string {
	var headers []string
	vals := make(http.Header)
	for k, vv := range signedHeaders {
		headers = append(headers, strings.ToLower(k))
		vals[strings.ToLower(k)] = vv
	}
	sort.Strings(headers)

	var buf bytes.Buffer
	for _, k := range headers {
		buf.WriteString(k)
		buf.WriteByte(':')
		for idx, v := range vals[k] {
			if idx > 0 {
				buf.WriteByte(',')
			}
			buf.WriteString(signV4TrimAll(v))
		}
		buf.WriteByte('\n')
	}
	return buf.String()
}

// getSignedHeaders generate a string i.e alphabetically sorted, semicolon-separated list of lowercase request header names
func getSignedHeaders(signedHeaders http.Header) string {
	var headers []string
	for k := range signedHeaders {
		headers = append(headers, strings.ToLower(k))
	}
	sort.Strings(headers)
	return strings.Join(headers, ";")
}

// getCanonicalRequest generate a canonical request of style
//
// canonicalRequest =
//  <HTTPMethod>\n
//  <CanonicalURI>\n
//  <CanonicalQueryString>\n
//  <CanonicalHeaders>\n
//  <SignedHeaders>\n
//  <HashedPayload>
//
func getCanonicalRequest(extractedSignedHeaders http.Header, payload, queryStr, urlPath, method string) string {
	rawQuery := strings.Replace(queryStr, "+", "%20", -1)
	encodedPath := s3utils.EncodePath(urlPath)
	canonicalRequest := strings.Join([]string{
		method,
		encodedPath,
		rawQuery,
		getCanonicalHeaders(extractedSignedHeaders),
		getSignedHeaders(extractedSignedHeaders),
		payload,
	}, "\n")
	return canonicalRequest
}

// getScope generate a string of a specific date, an AWS region, and a service.
func getScope(t time.Time, region string) string {
	scope := strings.Join([]string{
		t.Format(yyyymmdd),
		region,
		"s3",
		"aws4_request",
	}, "/")
	return scope
}

// getStringToSign a string based on selected query values.
func getStringToSign(canonicalRequest string, t time.Time, scope string) string {
	stringToSign := signV4Algorithm + "\n" + t.Format(iso8601Format) + "\n"
	stringToSign = stringToSign + scope + "\n"
	canonicalRequestBytes := sha256.Sum256([]byte(canonicalRequest))
	stringToSign = stringToSign + hex.EncodeToString(canonicalRequestBytes[:])
	return stringToSign
}

// getSigningKey hmac seed to calculate final signature.
func getSigningKey(secretKey string, t time.Time, region string) []byte {
	date := sumHMAC([]byte("AWS4"+secretKey), []byte(t.Format(yyyymmdd)))
	regionBytes := sumHMAC(date, []byte(region))
	service := sumHMAC(regionBytes, []byte("s3"))
	signingKey := sumHMAC(service, []byte("aws4_request"))
	return signingKey
}

// getSignature final signature in hexadecimal form.
func getSignature(signingKey []byte, stringToSign string) string {
	return hex.EncodeToString(sumHMAC(signingKey, []byte(stringToSign)))
}

// DoesPolicySignatureMatch - Check to see if Policy is signed correctly.
func DoesPolicySignatureMatch(formValues http.Header, accessKey, secretKey, region string) error {
	// For SignV2 - Signature field will be valid
	if _, ok := formValues["Signature"]; ok {
		return DoesPolicySignatureV2Match(formValues, accessKey, secretKey)
	}
	return DoesPolicySignatureV4Match(formValues, accessKey, secretKey, region)
}

// DoesPolicySignatureV4Match - Verify query headers with post policy
//     - http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-HTTPPOSTConstructPolicy.html
// returns nil if the signature matches.
func DoesPolicySignatureV4Match(formValues http.Header, accessKey, secretKey, region string) error {
	// Parse credential tag.
	credHeader, err := parseCredentialHeader("Credential="+formValues.Get("X-Amz-Credential"), accessKey)
	if err != nil {
		return MissingFields
	}

	// Verify if the access key id matches.
	if credHeader.accessKey != accessKey {
		return InvalidAccessKeyID
	}

	// Verify if region is valid.
	sRegion := credHeader.scope.region
	// Should validate region, only if region is set.
	if region == "" {
		region = sRegion
	}
	if !isValidRegion(sRegion, region) {
		return InvalidRegion
	}

	// Get signing key.
	signingKey := getSigningKey(secretKey, credHeader.scope.date, sRegion)

	// Get signature.
	newSignature := getSignature(signingKey, formValues.Get("Policy"))

	// Verify signature.
	if newSignature != formValues.Get("X-Amz-Signature") {
		return SignatureDoesNotMatch
	}

	// Success.
	return nil
}

// DoesPresignedSignV4Match - Verify query headers with presigned signature
//    - http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-query-string-auth.html
// returns nil if the signature matches.
func DoesPresignedSignV4Match(hashedPayload string, r *http.Request, accessKey, secretKey, region string) error {
	// Copy request
	req := *r

	// Parse request query string.
	pSignValues, err := parsePreSignV4(req.URL.Query(), accessKey)
	if err != nil {
		return err
	}

	// Verify if the access key id matches.
	if pSignValues.Credential.accessKey != accessKey {
		return InvalidAccessKeyID
	}

	// Verify if region is valid.
	sRegion := pSignValues.Credential.scope.region
	// Should validate region, only if region is set.
	if region == "" {
		region = sRegion
	}
	if !isValidRegion(sRegion, region) {
		return InvalidRegion
	}

	// Extract all the signed headers along with its values.
	extractedSignedHeaders, err := extractSignedHeaders(pSignValues.SignedHeaders, r)
	if err != nil {
		return err
	}
	// Construct new query.
	query := make(url.Values)
	if req.URL.Query().Get("X-Amz-Content-Sha256") != "" {
		query.Set("X-Amz-Content-Sha256", hashedPayload)
	}

	query.Set("X-Amz-Algorithm", signV4Algorithm)

	// If the host which signed the request is slightly ahead in time (by less than globalMaxSkewTime) the
	// request should still be allowed.
	if pSignValues.Date.After(time.Now().UTC().Add(15 * time.Minute)) {
		return RequestNotReadyYet
	}

	if time.Now().UTC().Sub(pSignValues.Date) > pSignValues.Expires {
		return ExpiredPresignRequest
	}

	// Save the date and expires.
	t := pSignValues.Date
	expireSeconds := int(pSignValues.Expires / time.Second)

	// Construct the query.
	query.Set("X-Amz-Date", t.Format(iso8601Format))
	query.Set("X-Amz-Expires", strconv.Itoa(expireSeconds))
	query.Set("X-Amz-SignedHeaders", getSignedHeaders(extractedSignedHeaders))
	query.Set("X-Amz-Credential", accessKey+"/"+getScope(t, sRegion))

	// Save other headers available in the request parameters.
	for k, v := range req.URL.Query() {
		if strings.HasPrefix(strings.ToLower(k), "x-amz") {
			continue
		}
		query[k] = v
	}

	// Get the encoded query.
	encodedQuery := query.Encode()

	// Verify if date query is same.
	if req.URL.Query().Get("X-Amz-Date") != query.Get("X-Amz-Date") {
		return SignatureDoesNotMatch
	}
	// Verify if expires query is same.
	if req.URL.Query().Get("X-Amz-Expires") != query.Get("X-Amz-Expires") {
		return SignatureDoesNotMatch
	}
	// Verify if signed headers query is same.
	if req.URL.Query().Get("X-Amz-SignedHeaders") != query.Get("X-Amz-SignedHeaders") {
		return SignatureDoesNotMatch
	}
	// Verify if credential query is same.
	if req.URL.Query().Get("X-Amz-Credential") != query.Get("X-Amz-Credential") {
		return SignatureDoesNotMatch
	}
	// Verify if sha256 payload query is same.
	if req.URL.Query().Get("X-Amz-Content-Sha256") != "" {
		if req.URL.Query().Get("X-Amz-Content-Sha256") != query.Get("X-Amz-Content-Sha256") {
			return SignatureDoesNotMatch
		}
	}

	/// Verify finally if signature is same.

	// Get canonical request.
	presignedCanonicalReq := getCanonicalRequest(extractedSignedHeaders, hashedPayload, encodedQuery, req.URL.Path, req.Method)

	// Get string to sign from canonical request.
	presignedStringToSign := getStringToSign(presignedCanonicalReq, t, pSignValues.Credential.getScope())

	// Get hmac presigned signing key.
	presignedSigningKey := getSigningKey(secretKey, pSignValues.Credential.scope.date, region)

	// Get new signature.
	newSignature := getSignature(presignedSigningKey, presignedStringToSign)

	// Verify signature.
	if req.URL.Query().Get("X-Amz-Signature") != newSignature {
		return SignatureDoesNotMatch
	}
	return nil
}

// DoesSignV4Match - Verify authorization header with calculated header in accordance with
//     - http://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-authenticating-requests.html
// returns nil if signature matches.
func DoesSignV4Match(hashedPayload string, r *http.Request, accessKey, secretKey string, region string) error {
	// Copy request.
	req := *r

	// Save authorization header.
	v4Auth := req.Header.Get("Authorization")

	// Parse signature version '4' header.
	signV4Values, err := parseSignV4(v4Auth, accessKey)
	if err != nil {
		return err
	}

	// Extract all the signed headers along with its values.
	extractedSignedHeaders, err := extractSignedHeaders(signV4Values.SignedHeaders, r)
	if err != nil {
		return err
	}

	// Verify if the access key id matches.
	if signV4Values.Credential.accessKey != accessKey {
		return InvalidAccessKeyID
	}

	// Extract date, if not present throw error.
	var date string
	if date = req.Header.Get(http.CanonicalHeaderKey("x-amz-date")); date == "" {
		if date = r.Header.Get("Date"); date == "" {
			return MissingDateHeader
		}
	}

	// Parse date header.
	t, e := time.Parse(iso8601Format, date)
	if e != nil {
		return MalformedDate
	}

	// Query string.
	queryStr := req.URL.Query().Encode()

	// Get canonical request.
	canonicalRequest := getCanonicalRequest(extractedSignedHeaders, hashedPayload, queryStr, req.URL.Path, req.Method)

	// Get string to sign from canonical request.
	stringToSign := getStringToSign(canonicalRequest, t, signV4Values.Credential.getScope())

	// Get hmac signing key.
	signingKey := getSigningKey(secretKey, signV4Values.Credential.scope.date, region)

	// Calculate signature.
	newSignature := getSignature(signingKey, stringToSign)

	// Verify if signature match.
	if newSignature != signV4Values.Signature {
		return SignatureDoesNotMatch
	}

	// Return error none.
	return nil
}
