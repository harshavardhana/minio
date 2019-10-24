/*
 * MinIO Cloud Storage, (C) 2019 MinIO, Inc.
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
 *
 */

package madmin

import (
	"io"
	"net/http"
	"net/url"
)

// HelpConfigKV - return help for a given sub-system.
func (adm *AdminClient) HelpConfigKV(subSys, key string, noColor bool) (io.ReadCloser, error) {
	v := url.Values{}
	v.Set("subSys", subSys)
	v.Set("key", key)
	if noColor {
		v.Set("noColor", "")
	}
	reqData := requestData{
		relPath:     adminAPIPrefix + "/help-config-kv",
		queryValues: v,
	}

	// Execute GET on /minio/admin/v2/help-config-kv
	resp, err := adm.executeMethod(http.MethodGet, reqData)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		defer closeResponse(resp)
		return nil, httpRespToErrorResponse(resp)
	}

	return resp.Body, nil

}
