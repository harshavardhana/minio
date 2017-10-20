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

package signer

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"github.com/minio/sha256-simd"
)

// http Header "x-amz-content-sha256" == "UNSIGNED-PAYLOAD" indicates that the
// client did not calculate sha256 of the payload.
const unsignedPayload = "UNSIGNED-PAYLOAD"

// SkipContentSha256Cksum - http Header "x-amz-content-sha256" == "UNSIGNED-PAYLOAD" indicates that the
// client did not calculate sha256 of the payload. Hence we skip calculating sha256.
// We also skip calculating sha256 for presigned requests without "x-amz-content-sha256"
// query header.
func SkipContentSha256Cksum(r *http.Request) bool {
	queryContentSha256 := r.URL.Query().Get("X-Amz-Content-Sha256")
	isRequestPresignedUnsignedPayload := func(r *http.Request) bool {
		if isRequestPresignedSignV4(r) {
			return queryContentSha256 == "" || queryContentSha256 == unsignedPayload
		}
		return false
	}
	return isRequestUnsignedPayload(r) || isRequestPresignedUnsignedPayload(r)
}

// GetContentSha256Cksum - Returns SHA256 for calculating canonical-request.
func GetContentSha256Cksum(r *http.Request) string {
	// For a presigned request we look at the query param for sha256.
	if isRequestPresignedSignV4(r) {
		presignedCkSum := r.URL.Query().Get("X-Amz-Content-Sha256")
		if presignedCkSum == "" {
			// If not set presigned is defaulted to UNSIGNED-PAYLOAD.
			return unsignedPayload
		}
		return presignedCkSum
	}
	contentCkSum := r.Header.Get("X-Amz-Content-Sha256")
	if contentCkSum == "" {
		// If not set content checksum is defaulted to sha256([]byte("")).
		contentCkSum = emptySHA256
	}
	return contentCkSum
}

// isValidRegion - verify if incoming region value is valid with configured Region.
func isValidRegion(reqRegion string, confRegion string) bool {
	if confRegion == "" {
		return true
	}
	if confRegion == "US" {
		confRegion = "us-east-1"
	}
	// Some older s3 clients set region as "US" instead of
	// globalMinioDefaultRegion, handle it.
	if reqRegion == "US" {
		reqRegion = "us-east-1"
	}
	return reqRegion == confRegion
}

// sumHMAC calculate hmac between two input byte array.
func sumHMAC(key []byte, data []byte) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write(data)
	return hash.Sum(nil)
}

func contains(stringList []string, element string) bool {
	for _, e := range stringList {
		if e == element {
			return true
		}
	}
	return false
}

// extractSignedHeaders extract signed headers from Authorization header
func extractSignedHeaders(signedHeaders []string, r *http.Request) (http.Header, error) {
	reqHeaders := r.Header
	// find whether "host" is part of list of signed headers.
	// if not return UnsignedHeaders. "host" is mandatory.
	if !contains(signedHeaders, "host") {
		return nil, UnsignedHeaders
	}
	extractedSignedHeaders := make(http.Header)
	for _, header := range signedHeaders {
		// `host` will not be found in the headers, can be found in r.Host.
		// but its alway necessary that the list of signed headers containing host in it.
		val, ok := reqHeaders[http.CanonicalHeaderKey(header)]
		if ok {
			for _, enc := range val {
				extractedSignedHeaders.Add(header, enc)
			}
			continue
		}
		switch header {
		case "expect":
			// Golang http server strips off 'Expect' header, if the
			// client sent this as part of signed headers we need to
			// handle otherwise we would see a signature mismatch.
			// `aws-cli` sets this as part of signed headers.
			//
			// According to
			// http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.20
			// Expect header is always of form:
			//
			//   Expect       =  "Expect" ":" 1#expectation
			//   expectation  =  "100-continue" | expectation-extension
			//
			// So it safe to assume that '100-continue' is what would
			// be sent, for the time being keep this work around.
			// Adding a *TODO* to remove this later when Golang server
			// doesn't filter out the 'Expect' header.
			extractedSignedHeaders.Set(header, "100-continue")
		case "host":
			// Go http server removes "host" from Request.Header
			extractedSignedHeaders.Set(header, r.Host)
		case "transfer-encoding":
			// Go http server removes "host" from Request.Header
			for _, enc := range r.TransferEncoding {
				extractedSignedHeaders.Add(header, enc)
			}
		case "content-length":
			// Signature-V4 spec excludes Content-Length from signed headers list for signature calculation.
			// But some clients deviate from this rule. Hence we consider Content-Length for signature
			// calculation to be compatible with such clients.
			extractedSignedHeaders.Set(header, strconv.FormatInt(r.ContentLength, 10))
		default:
			return nil, UnsignedHeaders
		}
	}
	return extractedSignedHeaders, nil
}

// Trim leading and trailing spaces and replace sequential spaces with one space, following Trimall()
// in http://docs.aws.amazon.com/general/latest/gr/sigv4-create-canonical-request.html
func signV4TrimAll(input string) string {
	// Compress adjacent spaces (a space is determined by
	// unicode.IsSpace() internally here) to one space and return
	return strings.Join(strings.Fields(input), " ")
}

// Verify if the request http Header "x-amz-content-sha256" == "UNSIGNED-PAYLOAD"
func isRequestUnsignedPayload(r *http.Request) bool {
	return r.Header.Get("x-amz-content-sha256") == unsignedPayload
}

// Verify if request has JWT.
func isRequestJWT(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), jwtAlgorithm)
}

// Verify if request has AWS Signature Version '4'.
func isRequestSignV4(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), signV4Algorithm)
}

// Verify if request has AWS Signature Version '2'.
func isRequestSignV2(r *http.Request) bool {
	return (!strings.HasPrefix(r.Header.Get("Authorization"), signV4Algorithm) &&
		strings.HasPrefix(r.Header.Get("Authorization"), signV2Algorithm))
}

// Verify if request has AWS PreSign Version '4'.
func isRequestPresignedSignV4(r *http.Request) bool {
	_, ok := r.URL.Query()["X-Amz-Credential"]
	return ok
}

// Verify request has AWS PreSign Version '2'.
func isRequestPresignedSignV2(r *http.Request) bool {
	_, ok := r.URL.Query()["AWSAccessKeyId"]
	return ok
}

// Verify if request has AWS Post policy Signature Version '4'.
func isRequestPostPolicySignV4(r *http.Request) bool {
	return strings.Contains(r.Header.Get("Content-Type"), "multipart/form-data") && r.Method == http.MethodPost
}

// Verify if the request has AWS Chunked Signature Version '4'. This is only valid for 'PUT' operation.
func isRequestChunkedSignV4(r *http.Request) bool {
	return r.Header.Get("x-amz-content-sha256") == chunkedContentSHA256 &&
		r.Method == http.MethodPut
}

// AuthType - Authorization type.
type AuthType int

// List of all supported Auth types.
const (
	AuthTypeUnknown AuthType = iota
	AuthTypeAnonymous
	AuthTypePresigned
	AuthTypePresignedV2
	AuthTypePostPolicy
	AuthTypeStreamingSigned
	AuthTypeSigned
	AuthTypeSignedV2
	AuthTypeJWT
)

// GetRequestAuthType Get request Authentication type.
func GetRequestAuthType(r *http.Request) AuthType {
	if isRequestSignV2(r) {
		return AuthTypeSignedV2
	} else if isRequestPresignedSignV2(r) {
		return AuthTypePresignedV2
	} else if isRequestChunkedSignV4(r) {
		return AuthTypeStreamingSigned
	} else if isRequestSignV4(r) {
		return AuthTypeSigned
	} else if isRequestPresignedSignV4(r) {
		return AuthTypePresigned
	} else if isRequestJWT(r) {
		return AuthTypeJWT
	} else if isRequestPostPolicySignV4(r) {
		return AuthTypePostPolicy
	} else if _, ok := r.Header["Authorization"]; !ok {
		return AuthTypeAnonymous
	}
	return AuthTypeUnknown
}

// IsReqAuthenticatedV2 - Verify if request has valid AWS Signature Version '2'.
func IsReqAuthenticatedV2(r *http.Request, accessKey, secretKey string) (err error) {
	if isRequestSignV2(r) {
		return DoesSignV2Match(r, accessKey, secretKey)
	}
	return DoesPresignV2SignatureMatch(r, accessKey, secretKey)
}

// ReqSignatureV4Verify -
func ReqSignatureV4Verify(r *http.Request, accessKey, secretKey, region string) (err error) {
	sha256sum := GetContentSha256Cksum(r)
	switch {
	case isRequestSignV4(r):
		return DoesSignV4Match(sha256sum, r, accessKey, secretKey, region)
	case isRequestPresignedSignV4(r):
		return DoesPresignedSignV4Match(sha256sum, r, accessKey, secretKey, region)
	default:
		return AccessDenied
	}
}

// IsReqAuthenticated - Verify if request has valid AWS Signature Version '4'.
func IsReqAuthenticated(r *http.Request, accessKey, secretKey, region string) (err error) {
	if r == nil {
		return InvalidRequest
	}

	if err = ReqSignatureV4Verify(r, accessKey, secretKey, region); err != nil {
		return err
	}

	var payload []byte
	payload, err = ioutil.ReadAll(r.Body)
	if err != nil {
		return InvalidRequest
	}

	// Populate back the payload.
	r.Body = ioutil.NopCloser(bytes.NewReader(payload))

	// Verify Content-Md5, if payload is set.
	if r.Header.Get("Content-Md5") != "" {
		md5Sum := md5.Sum(payload)
		if r.Header.Get("Content-Md5") != base64.StdEncoding.EncodeToString(md5Sum[:]) {
			return BadDigest
		}
	}

	if SkipContentSha256Cksum(r) {
		return nil
	}

	// Verify that X-Amz-Content-Sha256 Header == sha256(payload)
	// If X-Amz-Content-Sha256 header is not sent then we don't calculate/verify sha256(payload)
	sha256Hex := r.Header.Get("X-Amz-Content-Sha256")
	if isRequestPresignedSignV4(r) {
		sha256Hex = r.URL.Query().Get("X-Amz-Content-Sha256")
	}
	sha256Sum := sha256.Sum256(payload)
	if sha256Hex != "" && sha256Hex != hex.EncodeToString(sha256Sum[:]) {
		return ContentSHA256Mismatch
	}
	return nil
}

// List of all support S3 Auth types.
var supportedS3AuthTypes = map[AuthType]struct{}{
	AuthTypeAnonymous:       {},
	AuthTypePresigned:       {},
	AuthTypePresignedV2:     {},
	AuthTypeSigned:          {},
	AuthTypeSignedV2:        {},
	AuthTypePostPolicy:      {},
	AuthTypeStreamingSigned: {},
}

// IsSupportedS3AuthType - Validate if the AuthType is valid and supported.
func IsSupportedS3AuthType(aType AuthType) bool {
	_, ok := supportedS3AuthTypes[aType]
	return ok
}

// TrimAwsChunkedContentEncoding - Trims away `aws-chunked` from the content-encoding
// header if present. Streaming signature clients can have custom content-encoding such as
// `aws-chunked,gzip` here we need to only save `gzip`.
// For more refer http://docs.aws.amazon.com/AmazonS3/latest/API/sigv4-streaming.html
func TrimAwsChunkedContentEncoding(contentEnc string) (trimmedContentEnc string) {
	if contentEnc == "" {
		return contentEnc
	}
	var newEncs []string
	for _, enc := range strings.Split(contentEnc, ",") {
		if enc != streamingContentEncoding {
			newEncs = append(newEncs, enc)
		}
	}
	return strings.Join(newEncs, ",")
}
