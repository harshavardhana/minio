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
	"time"

	jwtgo "github.com/dgrijalva/jwt-go"
	jwtreq "github.com/dgrijalva/jwt-go/request"
)

const (
	jwtAlgorithm = "Bearer"
)

// GetAuthToken -
func GetAuthToken(accessKey, secretKey string, expiry time.Duration) (string, error) {
	utcNow := time.Now().UTC()
	token := jwtgo.NewWithClaims(jwtgo.SigningMethodHS512, jwtgo.StandardClaims{
		ExpiresAt: utcNow.Add(expiry).Unix(),
		IssuedAt:  utcNow.Unix(),
		Subject:   accessKey,
	})

	return token.SignedString([]byte(secretKey))
}

// IsAuthTokenValid -
func IsAuthTokenValid(tokenString string, accessKey, secretKey string) bool {
	if tokenString == "" {
		return false
	}
	var claims jwtgo.StandardClaims
	jwtToken, err := jwtgo.ParseWithClaims(tokenString, &claims, func(jwtToken *jwtgo.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwtgo.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", jwtToken.Header["alg"])
		}
		return []byte(secretKey), nil
	})
	if err != nil {
		return false
	}
	if err = claims.Valid(); err != nil {
		return false
	}
	return jwtToken.Valid && claims.Subject == accessKey
}

// WebRequestAuthenticate - Check if the request is authenticated.
// Returns nil if the request is authenticated. errNoAuthToken if token missing.
// Returns signer.TokenDoesNotMatch for all other errors.
func WebRequestAuthenticate(req *http.Request, accessKey, secretKey string) error {
	var claims jwtgo.StandardClaims
	jwtToken, err := jwtreq.ParseFromRequestWithClaims(req, jwtreq.AuthorizationHeaderExtractor, &claims,
		func(jwtToken *jwtgo.Token) (interface{}, error) {
			if _, ok := jwtToken.Method.(*jwtgo.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Unexpected signing method: %v", jwtToken.Header["alg"])
			}
			return []byte(secretKey), nil
		})
	if err != nil {
		if err == jwtreq.ErrNoTokenInRequest {
			return MissingToken
		}
		return TokenDoesNotMatch
	}
	if err = claims.Valid(); err != nil {
		return TokenDoesNotMatch
	}
	if claims.Subject != accessKey {
		return InvalidAccessKeyID
	}
	if !jwtToken.Valid {
		return TokenDoesNotMatch
	}
	return nil
}
