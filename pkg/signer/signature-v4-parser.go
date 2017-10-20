/*
 * Minio Cloud Storage, (C) 2015 Minio, Inc.
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
	"net/url"
	"strings"
	"time"
)

// credentialHeader data type represents structured form of Credential
// string from authorization header.
type credentialHeader struct {
	accessKey string
	scope     struct {
		date    time.Time
		region  string
		service string
		request string
	}
}

// Return scope string.
func (c credentialHeader) getScope() string {
	return strings.Join([]string{
		c.scope.date.Format(yyyymmdd),
		c.scope.region,
		c.scope.service,
		c.scope.request,
	}, "/")
}

// parse credentialHeader string into its structured form.
func parseCredentialHeader(credElement, accessKey string) (ch credentialHeader, err error) {
	creds := strings.Split(strings.TrimSpace(credElement), "=")
	if len(creds) != 2 {
		return ch, MissingFields
	}
	if creds[0] != "Credential" {
		return ch, MissingCredTag
	}
	credElements := strings.Split(strings.TrimSpace(creds[1]), "/")
	if len(credElements) != 5 {
		return ch, CredMalformed
	}

	if credElements[0] != accessKey {
		return ch, InvalidAccessKeyID
	}

	// Save access key id.
	cred := credentialHeader{
		accessKey: credElements[0],
	}

	cred.scope.date, err = time.Parse(yyyymmdd, credElements[1])
	if err != nil {
		return ch, MalformedCredentialDate
	}
	cred.scope.region = credElements[2]
	if credElements[3] != "s3" {
		return ch, InvalidService
	}
	cred.scope.service = credElements[3]
	if credElements[4] != "aws4_request" {
		return ch, InvalidRequestVersion
	}
	cred.scope.request = credElements[4]
	return cred, nil
}

// Parse signature from signature tag.
func parseSignature(signElement string) (string, error) {
	signFields := strings.Split(strings.TrimSpace(signElement), "=")
	if len(signFields) != 2 {
		return "", MissingFields
	}
	if signFields[0] != "Signature" {
		return "", MissingSignTag
	}
	if signFields[1] == "" {
		return "", MissingFields
	}
	signature := signFields[1]
	return signature, nil
}

// Parse slice of signed headers from signed headers tag.
func parseSignedHeader(signedHdrElement string) ([]string, error) {
	signedHdrFields := strings.Split(strings.TrimSpace(signedHdrElement), "=")
	if len(signedHdrFields) != 2 {
		return nil, MissingFields
	}
	if signedHdrFields[0] != "SignedHeaders" {
		return nil, MissingSignHeadersTag
	}
	if signedHdrFields[1] == "" {
		return nil, MissingFields
	}
	signedHeaders := strings.Split(signedHdrFields[1], ";")
	return signedHeaders, nil
}

// signValues data type represents structured form of AWS Signature V4 header.
type signValues struct {
	Credential    credentialHeader
	SignedHeaders []string
	Signature     string
}

// preSignValues data type represents structued form of AWS Signature V4 query string.
type preSignValues struct {
	signValues
	Date    time.Time
	Expires time.Duration
}

// Parses signature version '4' query string of the following form.
//
//   querystring = X-Amz-Algorithm=algorithm
//   querystring += &X-Amz-Credential= urlencode(accessKey + '/' + credential_scope)
//   querystring += &X-Amz-Date=date
//   querystring += &X-Amz-Expires=timeout interval
//   querystring += &X-Amz-SignedHeaders=signed_headers
//   querystring += &X-Amz-Signature=signature
//
// verifies if any of the necessary query params are missing in the presigned request.
func doesV4PresignParamsExist(query url.Values) error {
	v4PresignQueryParams := []string{"X-Amz-Algorithm", "X-Amz-Credential", "X-Amz-Signature", "X-Amz-Date", "X-Amz-SignedHeaders", "X-Amz-Expires"}
	for _, v4PresignQueryParam := range v4PresignQueryParams {
		if _, ok := query[v4PresignQueryParam]; !ok {
			return InvalidQueryParams
		}
	}
	return nil
}

// Parses all the presigned signature values into separate elements.
func parsePreSignV4(query url.Values, accessKey string) (psv preSignValues, err error) {
	// verify whether the required query params exist.
	if err = doesV4PresignParamsExist(query); err != nil {
		return psv, err
	}

	// Verify if the query algorithm is supported or not.
	if query.Get("X-Amz-Algorithm") != signV4Algorithm {
		return psv, InvalidQuerySignatureAlgo
	}

	// Initialize signature version '4' structured header.
	preSignV4Values := preSignValues{}

	// Save credential.
	preSignV4Values.Credential, err = parseCredentialHeader("Credential="+query.Get("X-Amz-Credential"), accessKey)
	if err != nil {
		return psv, err
	}

	// Save date in native time.Time.
	preSignV4Values.Date, err = time.Parse(iso8601Format, query.Get("X-Amz-Date"))
	if err != nil {
		return psv, MalformedPresignedDate
	}

	// Save expires in native time.Duration.
	preSignV4Values.Expires, err = time.ParseDuration(query.Get("X-Amz-Expires") + "s")
	if err != nil {
		return psv, MalformedExpires
	}

	if preSignV4Values.Expires < 0 {
		return psv, NegativeExpires
	}

	// Check if Expiry time is less than 7 days (value in seconds).
	if preSignV4Values.Expires.Seconds() > 604800 {
		return psv, MaximumExpires
	}

	// Save signed headers.
	preSignV4Values.SignedHeaders, err = parseSignedHeader("SignedHeaders=" + query.Get("X-Amz-SignedHeaders"))
	if err != nil {
		return psv, err
	}

	// Save signature.
	preSignV4Values.Signature, err = parseSignature("Signature=" + query.Get("X-Amz-Signature"))
	if err != nil {
		return psv, err
	}

	// Return structed form of signature query string.
	return preSignV4Values, nil
}

// Parses signature version '4' header of the following form.
//
//    Authorization: algorithm Credential=accessKeyID/credScope, \
//            SignedHeaders=signedHeaders, Signature=signature
//
func parseSignV4(v4Auth, accessKey string) (sv signValues, err error) {
	// Replace all spaced strings, some clients can send spaced
	// parameters and some won't. So we pro-actively remove any spaces
	// to make parsing easier.
	v4Auth = strings.Replace(v4Auth, " ", "", -1)
	if v4Auth == "" {
		return sv, AuthHeaderEmpty
	}

	// Verify if the header algorithm is supported or not.
	if !strings.HasPrefix(v4Auth, signV4Algorithm) {
		return sv, SignatureVersionNotSupported
	}

	// Strip off the Algorithm prefix.
	v4Auth = strings.TrimPrefix(v4Auth, signV4Algorithm)
	authFields := strings.Split(strings.TrimSpace(v4Auth), ",")
	if len(authFields) != 3 {
		return sv, MissingFields
	}

	// Initialize signature version '4' structured header.
	signV4Values := signValues{}

	// Save credential values.
	signV4Values.Credential, err = parseCredentialHeader(authFields[0], accessKey)
	if err != nil {
		return sv, err
	}

	// Save signed headers.
	signV4Values.SignedHeaders, err = parseSignedHeader(authFields[1])
	if err != nil {
		return sv, err
	}

	// Save signature.
	signV4Values.Signature, err = parseSignature(authFields[2])
	if err != nil {
		return sv, err
	}

	// Return the structure here.
	return signV4Values, nil
}
