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
	"fmt"
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestDoesPolicySignatureMatch(t *testing.T) {
	credentialTemplate := "%s/%s/%s/s3/aws4_request"
	now := time.Now().UTC()
	accessKey := "abcd123"

	testCases := []struct {
		form     http.Header
		expected error
	}{
		// (0) It should fail if 'X-Amz-Credential' is missing.
		{
			form:     http.Header{},
			expected: MissingFields,
		},
		// (1) It should fail if the access key is incorrect.
		{
			form: http.Header{
				"X-Amz-Credential": []string{fmt.Sprintf(credentialTemplate, "EXAMPLEINVALIDEXAMPL", now.Format(yyyymmdd), "us-east-1")},
			},
			expected: InvalidAccessKeyID,
		},
		// (2) It should fail with a bad signature.
		{
			form: http.Header{
				"X-Amz-Credential": []string{fmt.Sprintf(credentialTemplate, accessKey, now.Format(yyyymmdd), "us-east-1")},
				"X-Amz-Date":       []string{now.Format(iso8601Format)},
				"X-Amz-Signature":  []string{"invalidsignature"},
				"Policy":           []string{"policy"},
			},
			expected: SignatureDoesNotMatch,
		},
		// (3) It should succeed if everything is correct.
		{
			form: http.Header{
				"X-Amz-Credential": []string{
					fmt.Sprintf(credentialTemplate, accessKey, now.Format(yyyymmdd), "us-east-1"),
				},
				"X-Amz-Date": []string{now.Format(iso8601Format)},
				"X-Amz-Signature": []string{
					getSignature(getSigningKey("abcd123", now, "us-east-1"), "policy"),
				},
				"Policy": []string{"policy"},
			},
			expected: nil,
		},
	}

	// Run each test case individually.
	for i, testCase := range testCases {
		code := DoesPolicySignatureMatch(testCase.form, accessKey, "abcd123", "us-east-1")
		if code != testCase.expected {
			t.Errorf("(%d) expected to get %s, instead got %s", i, testCase.expected, code)
		}
	}
}

func TestDoesPresignedSignatureMatch(t *testing.T) {
	// sha256 hash of "payload"
	payloadSHA256 := "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5"
	now := time.Now().UTC()
	credentialTemplate := "%s/%s/%s/s3/aws4_request"

	region := "us-east-1"
	accessKeyID := "abcd123"
	testCases := []struct {
		queryParams map[string]string
		headers     map[string]string
		region      string
		expected    error
	}{
		// (0) Should error without a set URL query.
		{
			region:   "us-east-1",
			expected: InvalidQueryParams,
		},
		// (1) Should error on an invalid access key.
		{
			queryParams: map[string]string{
				"X-Amz-Algorithm":     signV4Algorithm,
				"X-Amz-Date":          now.Format(iso8601Format),
				"X-Amz-Expires":       "60",
				"X-Amz-Signature":     "badsignature",
				"X-Amz-SignedHeaders": "host;x-amz-content-sha256;x-amz-date",
				"X-Amz-Credential":    fmt.Sprintf(credentialTemplate, "Z7IXGOO6BZ0REAN1Q26I", now.Format(yyyymmdd), "us-west-1"),
			},
			region:   "us-west-1",
			expected: InvalidAccessKeyID,
		},
		// (2) Should NOT fail with an invalid region if it doesn't verify it.
		{
			queryParams: map[string]string{
				"X-Amz-Algorithm":      signV4Algorithm,
				"X-Amz-Date":           now.Format(iso8601Format),
				"X-Amz-Expires":        "60",
				"X-Amz-Signature":      "badsignature",
				"X-Amz-SignedHeaders":  "host;x-amz-content-sha256;x-amz-date",
				"X-Amz-Credential":     fmt.Sprintf(credentialTemplate, accessKeyID, now.Format(yyyymmdd), "us-west-1"),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			region:   "us-west-1",
			expected: UnsignedHeaders,
		},
		// (3) Should fail to extract headers if the host header is not signed.
		{
			queryParams: map[string]string{
				"X-Amz-Algorithm":      signV4Algorithm,
				"X-Amz-Date":           now.Format(iso8601Format),
				"X-Amz-Expires":        "60",
				"X-Amz-Signature":      "badsignature",
				"X-Amz-SignedHeaders":  "x-amz-content-sha256;x-amz-date",
				"X-Amz-Credential":     fmt.Sprintf(credentialTemplate, accessKeyID, now.Format(yyyymmdd), region),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			region:   region,
			expected: UnsignedHeaders,
		},
		// (4) Should give an expired request if it has expired.
		{
			queryParams: map[string]string{
				"X-Amz-Algorithm":      signV4Algorithm,
				"X-Amz-Date":           now.AddDate(0, 0, -2).Format(iso8601Format),
				"X-Amz-Expires":        "60",
				"X-Amz-Signature":      "badsignature",
				"X-Amz-SignedHeaders":  "host;x-amz-content-sha256;x-amz-date",
				"X-Amz-Credential":     fmt.Sprintf(credentialTemplate, accessKeyID, now.Format(yyyymmdd), region),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			headers: map[string]string{
				"X-Amz-Date":           now.AddDate(0, 0, -2).Format(iso8601Format),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			region:   region,
			expected: ExpiredPresignRequest,
		},
		// (5) Should error if the signature is incorrect.
		{
			queryParams: map[string]string{
				"X-Amz-Algorithm":      signV4Algorithm,
				"X-Amz-Date":           now.Format(iso8601Format),
				"X-Amz-Expires":        "60",
				"X-Amz-Signature":      "badsignature",
				"X-Amz-SignedHeaders":  "host;x-amz-content-sha256;x-amz-date",
				"X-Amz-Credential":     fmt.Sprintf(credentialTemplate, accessKeyID, now.Format(yyyymmdd), region),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			headers: map[string]string{
				"X-Amz-Date":           now.Format(iso8601Format),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			region:   region,
			expected: SignatureDoesNotMatch,
		},
		// (6) Should error if the request is not ready yet, ie X-Amz-Date is in the future.
		{
			queryParams: map[string]string{
				"X-Amz-Algorithm":      signV4Algorithm,
				"X-Amz-Date":           now.Add(1 * time.Hour).Format(iso8601Format),
				"X-Amz-Expires":        "60",
				"X-Amz-Signature":      "badsignature",
				"X-Amz-SignedHeaders":  "host;x-amz-content-sha256;x-amz-date",
				"X-Amz-Credential":     fmt.Sprintf(credentialTemplate, accessKeyID, now.Format(yyyymmdd), region),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			headers: map[string]string{
				"X-Amz-Date":           now.Format(iso8601Format),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			region:   region,
			expected: RequestNotReadyYet,
		},
		// (7) Should not error with invalid region instead, call should proceed
		// with sigature does not match.
		{
			queryParams: map[string]string{
				"X-Amz-Algorithm":      signV4Algorithm,
				"X-Amz-Date":           now.Format(iso8601Format),
				"X-Amz-Expires":        "60",
				"X-Amz-Signature":      "badsignature",
				"X-Amz-SignedHeaders":  "host;x-amz-content-sha256;x-amz-date",
				"X-Amz-Credential":     fmt.Sprintf(credentialTemplate, accessKeyID, now.Format(yyyymmdd), region),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			headers: map[string]string{
				"X-Amz-Date":           now.Format(iso8601Format),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			region:   "",
			expected: SignatureDoesNotMatch,
		},
		// (8) Should error with signature does not match. But handles
		// query params which do not precede with "x-amz-" header.
		{
			queryParams: map[string]string{
				"X-Amz-Algorithm":       signV4Algorithm,
				"X-Amz-Date":            now.Format(iso8601Format),
				"X-Amz-Expires":         "60",
				"X-Amz-Signature":       "badsignature",
				"X-Amz-SignedHeaders":   "host;x-amz-content-sha256;x-amz-date",
				"X-Amz-Credential":      fmt.Sprintf(credentialTemplate, accessKeyID, now.Format(yyyymmdd), region),
				"X-Amz-Content-Sha256":  payloadSHA256,
				"response-content-type": "application/json",
			},
			headers: map[string]string{
				"X-Amz-Date":           now.Format(iso8601Format),
				"X-Amz-Content-Sha256": payloadSHA256,
			},
			region:   "",
			expected: SignatureDoesNotMatch,
		},
		// (9) Should error with unsigned headers.
		{
			queryParams: map[string]string{
				"X-Amz-Algorithm":       signV4Algorithm,
				"X-Amz-Date":            now.Format(iso8601Format),
				"X-Amz-Expires":         "60",
				"X-Amz-Signature":       "badsignature",
				"X-Amz-SignedHeaders":   "host;x-amz-content-sha256;x-amz-date",
				"X-Amz-Credential":      fmt.Sprintf(credentialTemplate, accessKeyID, now.Format(yyyymmdd), region),
				"X-Amz-Content-Sha256":  payloadSHA256,
				"response-content-type": "application/json",
			},
			headers: map[string]string{
				"X-Amz-Date": now.Format(iso8601Format),
			},
			region:   "",
			expected: UnsignedHeaders,
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
		req, e := http.NewRequest(http.MethodGet, "http://host/a/b?"+query.Encode(), nil)
		if e != nil {
			t.Errorf("(%d) failed to create http.Request, got %v", i, e)
		}

		// Do the same for the headers.
		for key, value := range testCase.headers {
			req.Header.Set(key, value)
		}

		// Check if it matches!
		err := DoesPresignedSignV4Match(payloadSHA256, req, "abcd123", "abcd123", testCase.region)
		if err != testCase.expected {
			t.Errorf("(%d) expected to get %s, instead got %s", i, testCase.expected, err)
		}
	}
}
