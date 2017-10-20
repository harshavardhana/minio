/*
 * Minio Cloud Storage, (C) 2017 Minio, Inc.
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
	"net/http"
	"net/url"
	"testing"
)

// Test get request auth type.
func TestGetRequestAuthType(t *testing.T) {
	type testCase struct {
		req   *http.Request
		authT AuthType
	}
	testCases := []testCase{
		// Test case - 1
		// Check for generic signature v4 header.
		{
			req: &http.Request{
				URL: &url.URL{
					Host:   "127.0.0.1:9000",
					Scheme: httpScheme,
					Path:   "/",
				},
				Header: http.Header{
					"Authorization":        []string{"AWS4-HMAC-SHA256 <cred_string>"},
					"X-Amz-Content-Sha256": []string{"STREAMING-AWS4-HMAC-SHA256-PAYLOAD"},
					"Content-Encoding":     []string{"aws-chunked"},
				},
				Method: "PUT",
			},
			authT: AuthTypeStreamingSigned,
		},
		// Test case - 2
		// Check for JWT header.
		{
			req: &http.Request{
				URL: &url.URL{
					Host:   "127.0.0.1:9000",
					Scheme: httpScheme,
					Path:   "/",
				},
				Header: http.Header{
					"Authorization": []string{"Bearer 12313123"},
				},
			},
			authT: AuthTypeJWT,
		},
		// Test case - 3
		// Empty authorization header.
		{
			req: &http.Request{
				URL: &url.URL{
					Host:   "127.0.0.1:9000",
					Scheme: httpScheme,
					Path:   "/",
				},
				Header: http.Header{
					"Authorization": []string{""},
				},
			},
			authT: AuthTypeUnknown,
		},
		// Test case - 4
		// Check for presigned.
		{
			req: &http.Request{
				URL: &url.URL{
					Host:     "127.0.0.1:9000",
					Scheme:   httpScheme,
					Path:     "/",
					RawQuery: "X-Amz-Credential=EXAMPLEINVALIDEXAMPL%2Fs3%2F20160314%2Fus-east-1",
				},
			},
			authT: AuthTypePresigned,
		},
		// Test case - 5
		// Check for post policy.
		{
			req: &http.Request{
				URL: &url.URL{
					Host:   "127.0.0.1:9000",
					Scheme: httpScheme,
					Path:   "/",
				},
				Header: http.Header{
					"Content-Type": []string{"multipart/form-data"},
				},
				Method: "POST",
			},
			authT: AuthTypePostPolicy,
		},
	}

	// .. Tests all request auth type.
	for i, testc := range testCases {
		authT := GetRequestAuthType(testc.req)
		if authT != testc.authT {
			t.Errorf("Test %d: Expected %d, got %d", i+1, testc.authT, authT)
		}
	}
}

// Test all s3 supported auth types.
func TestS3SupportedAuthType(t *testing.T) {
	type testCase struct {
		authT AuthType
		pass  bool
	}
	// List of all valid and invalid test cases.
	testCases := []testCase{
		// Test 1 - supported s3 type anonymous.
		{
			authT: AuthTypeAnonymous,
			pass:  true,
		},
		// Test 2 - supported s3 type presigned.
		{
			authT: AuthTypePresigned,
			pass:  true,
		},
		// Test 3 - supported s3 type signed.
		{
			authT: AuthTypeSigned,
			pass:  true,
		},
		// Test 4 - supported s3 type with post policy.
		{
			authT: AuthTypePostPolicy,
			pass:  true,
		},
		// Test 5 - supported s3 type with streaming signed.
		{
			authT: AuthTypeStreamingSigned,
			pass:  true,
		},
		// Test 6 - supported s3 type with signature v2.
		{
			authT: AuthTypeSignedV2,
			pass:  true,
		},
		// Test 7 - supported s3 type with presign v2.
		{
			authT: AuthTypePresignedV2,
			pass:  true,
		},
		// Test 8 - JWT is not supported s3 type.
		{
			authT: AuthTypeJWT,
			pass:  false,
		},
		// Test 9 - unknown auth header is not supported s3 type.
		{
			authT: AuthTypeUnknown,
			pass:  false,
		},
		// Test 10 - some new auth type is not supported s3 type.
		{
			authT: AuthType(9),
			pass:  false,
		},
	}
	// Validate all the test cases.
	for i, tt := range testCases {
		ok := IsSupportedS3AuthType(tt.authT)
		if ok != tt.pass {
			t.Errorf("Test %d:, Expected %t, got %t", i+1, tt.pass, ok)
		}
	}
}

// TestIsRequestUnsignedPayload - Test validates the Unsigned payload detection logic.
func TestIsRequestUnsignedPayload(t *testing.T) {
	testCases := []struct {
		inputAmzContentHeader string
		expectedResult        bool
	}{
		// Test case - 1.
		// Test case with "X-Amz-Content-Sha256" header set to empty value.
		{"", false},
		// Test case - 2.
		// Test case with "X-Amz-Content-Sha256" header set to  "UNSIGNED-PAYLOAD"
		// The payload is flagged as unsigned When "X-Amz-Content-Sha256" header is set to  "UNSIGNED-PAYLOAD".
		{unsignedPayload, true},
		// Test case - 3.
		// set to a random value.
		{"abcd", false},
	}

	// creating an input HTTP request.
	// Only the headers are relevant for this particular test.
	inputReq, err := http.NewRequest("GET", "http://example.com", nil)
	if err != nil {
		t.Fatalf("Error initializing input HTTP request: %v", err)
	}

	for i, testCase := range testCases {
		inputReq.Header.Set("X-Amz-Content-Sha256", testCase.inputAmzContentHeader)
		actualResult := isRequestUnsignedPayload(inputReq)
		if testCase.expectedResult != actualResult {
			t.Errorf("Test %d: Expected the result to `%v`, but instead got `%v`", i+1, testCase.expectedResult, actualResult)
		}
	}
}

func TestIsRequestPresignedSignatureV2(t *testing.T) {
	testCases := []struct {
		inputQueryKey   string
		inputQueryValue string
		expectedResult  bool
	}{
		// Test case - 1.
		// Test case with query key "AWSAccessKeyId" set.
		{"", "", false},
		// Test case - 2.
		{"AWSAccessKeyId", "", true},
		// Test case - 3.
		{"X-Amz-Content-Sha256", "", false},
	}

	for i, testCase := range testCases {
		// creating an input HTTP request.
		// Only the query parameters are relevant for this particular test.
		inputReq, err := http.NewRequest("GET", "http://example.com", nil)
		if err != nil {
			t.Fatalf("Error initializing input HTTP request: %v", err)
		}
		q := inputReq.URL.Query()
		q.Add(testCase.inputQueryKey, testCase.inputQueryValue)
		inputReq.URL.RawQuery = q.Encode()

		actualResult := isRequestPresignedSignV2(inputReq)
		if testCase.expectedResult != actualResult {
			t.Errorf("Test %d: Expected the result to `%v`, but instead got `%v`", i+1, testCase.expectedResult, actualResult)
		}
	}
}

// TestIsRequestPresignedSignatureV4 - Test validates the logic for presign signature verision v4 detection.
func TestIsRequestPresignedSignatureV4(t *testing.T) {
	testCases := []struct {
		inputQueryKey   string
		inputQueryValue string
		expectedResult  bool
	}{
		// Test case - 1.
		// Test case with query key ""X-Amz-Credential" set.
		{"", "", false},
		// Test case - 2.
		{"X-Amz-Credential", "", true},
		// Test case - 3.
		{"X-Amz-Content-Sha256", "", false},
	}

	for i, testCase := range testCases {
		// creating an input HTTP request.
		// Only the query parameters are relevant for this particular test.
		inputReq, err := http.NewRequest("GET", "http://example.com", nil)
		if err != nil {
			t.Fatalf("Error initializing input HTTP request: %v", err)
		}
		q := inputReq.URL.Query()
		q.Add(testCase.inputQueryKey, testCase.inputQueryValue)
		inputReq.URL.RawQuery = q.Encode()

		actualResult := isRequestPresignedSignV4(inputReq)
		if testCase.expectedResult != actualResult {
			t.Errorf("Test %d: Expected the result to `%v`, but instead got `%v`", i+1, testCase.expectedResult, actualResult)
		}
	}
}
