/*
 * Minio Cloud Storage, (C) 2015, 2016 Minio, Inc.
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

package cmd

import (
	"net/http"

	"github.com/minio/minio/pkg/signer"
)

func checkRequestAuthType(r *http.Request, bucket, policyAction, region string) APIErrorCode {
	reqAuthType := signer.GetRequestAuthType(r)

	cred := serverConfig.GetCredential()
	switch reqAuthType {
	case signer.AuthTypePresignedV2, signer.AuthTypeSignedV2:
		// Signature V2 validation.
		if err := signer.IsReqAuthenticatedV2(r, cred.AccessKey, cred.SecretKey); err != nil {
			errorIf(err, "%s", dumpRequest(r))
		}
		return ErrNone
	case signer.AuthTypeSigned, signer.AuthTypePresigned:
		if err := signer.IsReqAuthenticated(r, cred.AccessKey, cred.SecretKey, region); err != nil {
			errorIf(err, "%s", dumpRequest(r))
		}
		return ErrNone
	}

	if reqAuthType == signer.AuthTypeAnonymous && policyAction != "" {
		// http://docs.aws.amazon.com/AmazonS3/latest/dev/using-with-s3-actions.html
		sourceIP := getSourceIPAddress(r)
		resource, err := getResource(r.URL.Path, r.Host, globalDomainName)
		if err != nil {
			return ErrInternalError
		}
		return enforceBucketPolicy(bucket, policyAction, resource,
			r.Referer(), sourceIP, r.URL.Query())
	}

	// By default return AccessDenied
	return ErrAccessDenied
}

// authHandler - handles all the incoming authorization headers and validates them if possible.
type authHandler struct {
	handler http.Handler
}

// setAuthHandler to validate authorization header for the incoming request.
func setAuthHandler(h http.Handler) http.Handler {
	return authHandler{h}
}

// handler for validating incoming authorization headers.
func (a authHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	cred := serverConfig.GetCredential()
	aType := signer.GetRequestAuthType(r)
	if signer.IsSupportedS3AuthType(aType) {
		// Let top level caller validate for anonymous and known signed requests.
		a.handler.ServeHTTP(w, r)
		return
	} else if aType == signer.AuthTypeJWT {
		// Validate Authorization header if its valid for JWT request.
		if signer.WebRequestAuthenticate(r, cred.AccessKey, cred.SecretKey) != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		a.handler.ServeHTTP(w, r)
		return
	}
	writeErrorResponse(w, ErrSignatureVersionNotSupported, r.URL)
}
