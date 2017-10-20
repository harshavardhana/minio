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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Tests for 'func TestResourceListSorting(t *testing.T)'.
func TestResourceListSorting(t *testing.T) {
	sortedResourceList := make([]string, len(resourceList))
	copy(sortedResourceList, resourceList)
	sort.Strings(sortedResourceList)
	for i := 0; i < len(resourceList); i++ {
		if resourceList[i] != sortedResourceList[i] {
			t.Errorf("Expected resourceList[%d] = \"%s\", resourceList is not correctly sorted.", i, sortedResourceList[i])
			break
		}
	}
}

// preSignV2 - presign the request in following style.
// https://${S3_BUCKET}.s3.amazonaws.com/${S3_OBJECT}?AWSAccessKeyId=${S3_ACCESS_KEY}&Expires=${TIMESTAMP}&Signature=${SIGNATURE}.
func preSignV2(req *http.Request, accessKeyID, secretAccessKey string, expires int64) error {
	// Presign is not needed for anonymous credentials.
	if accessKeyID == "" || secretAccessKey == "" {
		return errors.New("Presign cannot be generated without access and secret keys")
	}

	// FIXME: Remove following portion of code after fixing a bug in minio-go preSignV2.

	d := time.Now().UTC()
	// Find epoch expires when the request will expire.
	epochExpires := d.Unix() + expires

	// Add expires header if not present.
	expiresStr := req.Header.Get("Expires")
	if expiresStr == "" {
		expiresStr = strconv.FormatInt(epochExpires, 10)
		req.Header.Set("Expires", expiresStr)
	}

	// url.RawPath will be valid if path has any encoded characters, if not it will
	// be empty - in which case we need to consider url.Path (bug in net/http?)
	encodedResource := req.URL.RawPath
	encodedQuery := req.URL.RawQuery
	if encodedResource == "" {
		splits := strings.SplitN(req.URL.Path, "?", 2)
		encodedResource = splits[0]
		if len(splits) == 2 {
			encodedQuery = splits[1]
		}
	}

	unescapedQueries, err := unescapeQueries(encodedQuery)
	if err != nil {
		return err
	}

	// Get presigned string to sign.
	stringToSign := getStringToSignV2(req.Method, encodedResource, strings.Join(unescapedQueries, "&"), req.Header, expiresStr)
	hm := hmac.New(sha1.New, []byte(secretAccessKey))
	hm.Write([]byte(stringToSign))

	// Calculate signature.
	signature := base64.StdEncoding.EncodeToString(hm.Sum(nil))

	query := req.URL.Query()
	// Handle specially for Google Cloud Storage.
	query.Set("AWSAccessKeyId", accessKeyID)
	// Fill in Expires for presigned query.
	query.Set("Expires", strconv.FormatInt(epochExpires, 10))

	// Encode query and save.
	req.URL.RawQuery = query.Encode()

	// Save signature finally.
	req.URL.RawQuery += "&Signature=" + url.QueryEscape(signature)
	return nil
}

// Tests presigned v2 signature.
func TestDoesPresignedV2SignatureMatch(t *testing.T) {
	now := time.Now().UTC()

	var (
		accessKey = "myuser"
		secretKey = "myuser123"
	)
	testCases := []struct {
		queryParams map[string]string
		expected    error
	}{
		// (0) Should error without a set URL query.
		{
			expected: InvalidQueryParams,
		},
		// (1) Should error on an invalid access key.
		{
			queryParams: map[string]string{
				"Expires":        "60",
				"Signature":      "badsignature",
				"AWSAccessKeyId": "Z7IXGOO6BZ0REAN1Q26I",
			},
			expected: InvalidAccessKeyID,
		},
		// (2) Should error with malformed expires.
		{
			queryParams: map[string]string{
				"Expires":        "60s",
				"Signature":      "badsignature",
				"AWSAccessKeyId": accessKey,
			},
			expected: MalformedExpires,
		},
		// (3) Should give an expired request if it has expired.
		{
			queryParams: map[string]string{
				"Expires":        "60",
				"Signature":      "badsignature",
				"AWSAccessKeyId": accessKey,
			},
			expected: ExpiredPresignRequest,
		},
		// (4) Should error when the signature does not match.
		{
			queryParams: map[string]string{
				"Expires":        fmt.Sprintf("%d", now.Unix()+60),
				"Signature":      "badsignature",
				"AWSAccessKeyId": accessKey,
			},
			expected: SignatureDoesNotMatch,
		},
		// (5) Should error when the signature does not match.
		{
			queryParams: map[string]string{
				"Expires":        fmt.Sprintf("%d", now.Unix()+60),
				"Signature":      "zOM2YrY/yAQe15VWmT78OlBrK6g=",
				"AWSAccessKeyId": accessKey,
			},
			expected: SignatureDoesNotMatch,
		},
		// (6) Should not error signature matches with extra query params.
		{
			queryParams: map[string]string{
				"response-content-disposition": "attachment; filename=\"4K%2d4M.txt\"",
			},
			expected: nil,
		},
		// (7) Should not error signature matches with no special query params.
		{
			queryParams: map[string]string{},
			expected:    nil,
		},
	}

	// Run each test case individually.
	for i, testCase := range testCases {
		// Turn the map[string]string into map[string][]string, because Go.
		query := url.Values{}
		for key, value := range testCase.queryParams {
			query.Set(key, value)
		}
		// Create a request to use.
		req, err := http.NewRequest(http.MethodGet, "http://host/a/b?"+query.Encode(), nil)
		if err != nil {
			t.Errorf("(%d) failed to create http.Request, got %v", i, err)
		}
		if testCase.expected != nil {
			// Should be set since we are simulating a http server.
			req.RequestURI = req.URL.RequestURI()
			// Check if it matches!
			errCode := DoesPresignV2SignatureMatch(req, accessKey, secretKey)
			if errCode != testCase.expected {
				t.Errorf("(%d) expected to get %s, instead got %s", i, testCase.expected, errCode)
			}
		} else {
			err = preSignV2(req, accessKey, secretKey, now.Unix()+60)
			if err != nil {
				t.Fatalf("(%d) failed to preSignV2 http request, got %v", i, err)
			}
			// Should be set since we are simulating a http server.
			req.RequestURI = req.URL.RequestURI()
			errCode := DoesPresignV2SignatureMatch(req, accessKey, secretKey)
			if errCode != testCase.expected {
				t.Errorf("(%d) expected to get success, instead got %s", i, errCode)
			}
		}

	}
}

// TestValidateV2AuthHeader - Tests validate the logic of V2 Authorization header validator.
func TestValidateV2AuthHeader(t *testing.T) {
	accessID := "myuser"
	testCases := []struct {
		authString string
		expectedor error
	}{
		// Test case - 1.
		// Case with empty V2AuthString.
		{

			authString: "",
			expectedor: AuthHeaderEmpty,
		},
		// Test case - 2.
		// Test case with `signV2Algorithm` ("AWS") not being the prefix.
		{

			authString: "NoV2Prefix",
			expectedor: SignatureVersionNotSupported,
		},
		// Test case - 3.
		// Test case with missing parts in the Auth string.
		// below is the correct format of V2 Authorization header.
		// Authorization = "AWS" + " " + AWSAccessKeyId + ":" + Signature
		{

			authString: signV2Algorithm,
			expectedor: MissingFields,
		},
		// Test case - 4.
		// Test case with signature part missing.
		{

			authString: fmt.Sprintf("%s %s", signV2Algorithm, accessID),
			expectedor: MissingFields,
		},
		// Test case - 5.
		// Test case with wrong accessID.
		{

			authString: fmt.Sprintf("%s %s:%s", signV2Algorithm, "InvalidAccessID", "signature"),
			expectedor: InvalidAccessKeyID,
		},
		// Test case - 6.
		// Case with right accessID and format.
		{

			authString: fmt.Sprintf("%s %s:%s", signV2Algorithm, accessID, "signature"),
			expectedor: nil,
		},
	}

	for i, testCase := range testCases {
		t.Run(fmt.Sprintf("Case %d AuthStr \"%s\".", i+1, testCase.authString), func(t *testing.T) {

			actualCode := validateV2AuthHeader(testCase.authString, accessID)

			if testCase.expectedor != actualCode {
				t.Errorf("Expected the error code to be %v, got %v.", testCase.expectedor, actualCode)
			}
		})
	}

}

func TestDoesPolicySignatureV2Match(t *testing.T) {
	policy := "policy"
	testCases := []struct {
		accessKey string
		policy    string
		signature string
		errCode   error
	}{
		{"invalidAccessKey", policy, calculateSignatureV2(policy, "myuser123"), InvalidAccessKeyID},
		{"myuser", policy, calculateSignatureV2("random", "myuser12"), SignatureDoesNotMatch},
		{"myuser", policy, calculateSignatureV2(policy, "myuser123"), nil},
	}
	for i, test := range testCases {
		formValues := make(http.Header)
		formValues.Set("Awsaccesskeyid", test.accessKey)
		formValues.Set("Signature", test.signature)
		formValues.Set("Policy", test.policy)
		errCode := DoesPolicySignatureV2Match(formValues, "myuser", "myuser123")
		if errCode != test.errCode {
			t.Fatalf("(%d) expected to get %s, instead got %s", i+1, test.errCode, errCode)
		}
	}
}
