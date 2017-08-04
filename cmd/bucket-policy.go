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
	"bytes"
	"sync"

	"github.com/minio/minio-go/pkg/policy"
)

const (
	// Static prefix to be used while constructing bucket ARN.
	// refer to S3 docs for more info.
	bucketARNPrefix = "arn:" + eventSource + ":::"

	// Bucket policy config name.
	bucketPolicyConfig = "policy.json"
)

// Variable represents bucket policies in memory.
var globalBucketPolicies *bucketPolicies

// Global bucket policies list, policies are enforced on each bucket looking
// through the policies here.
type bucketPolicies struct {
	rwMutex *sync.RWMutex

	// Collection of 'bucket' policies.
	bucketPolicyConfigs map[string]policy.BucketAccessPolicy
}

// Fetch bucket policy for a given bucket.
func (bp bucketPolicies) GetBucketPolicy(bucket string) policy.BucketAccessPolicy {
	bp.rwMutex.RLock()
	defer bp.rwMutex.RUnlock()
	return bp.bucketPolicyConfigs[bucket]
}

// Set a new bucket policy for a bucket, this operation will overwrite
// any previous bucket policies for the bucket.
func (bp *bucketPolicies) SetBucketPolicy(bucket string, p policy.BucketAccessPolicy) error {
	bp.rwMutex.Lock()
	defer bp.rwMutex.Unlock()

	if len(p.Statements) == 0 {
		delete(bp.bucketPolicyConfigs, bucket)
	} else {
		bp.bucketPolicyConfigs[bucket] = p
	}
	return nil
}

// Loads all bucket policies from persistent layer.
func loadAllBucketPolicies(objAPI ObjectLayer) (policies map[string]policy.BucketAccessPolicy, err error) {
	// List buckets to proceed loading all notification configuration.
	buckets, err := objAPI.ListBuckets()
	errorIf(err, "Unable to list buckets.")
	if err != nil {
		return nil, errorCause(err)
	}

	policies = make(map[string]policy.BucketAccessPolicy)
	var pErrs []error
	// Loads bucket policy.
	for _, bucket := range buckets {
		policy, pErr := objAPI.GetBucketPolicies(bucket.Name)
		if pErr != nil {
			// net.Dial fails for rpc client or any
			// other unexpected errors during net.Dial.
			if !isErrIgnored(pErr, errDiskNotFound) {
				if !isErrBucketPolicyNotFound(pErr) {
					pErrs = append(pErrs, pErr)
				}
			}
			// Continue to load other bucket policies if possible.
			continue
		}
		policies[bucket.Name] = policy
	}

	// Look for any errors occurred while reading bucket policies.
	for _, pErr := range pErrs {
		if pErr != nil {
			return policies, pErr
		}
	}

	// Success.
	return policies, nil
}

// Intialize all bucket policies.
func initBucketPolicies(objAPI ObjectLayer) error {
	if objAPI == nil {
		return errInvalidArgument
	}

	// Read all bucket policies.
	policies, err := loadAllBucketPolicies(objAPI)
	if err != nil {
		return err
	}

	// Populate global bucket collection.
	globalBucketPolicies = &bucketPolicies{
		rwMutex:             &sync.RWMutex{},
		bucketPolicyConfigs: policies,
	}

	// Success.
	return nil
}

func parseAndPersistBucketPolicy(bucket string, policyBytes []byte, objAPI ObjectLayer) APIErrorCode {
	// Parse bucket policy.
	var bktPolicy policy.BucketAccessPolicy
	err := parseBucketPolicy(bytes.NewReader(policyBytes), &bktPolicy)
	if err != nil {
		errorIf(err, "Unable to parse bucket policy.")
		return ErrInvalidPolicyDocument
	}

	// Parse check bucket policy.
	if s3Error := checkBucketPolicyResources(bucket, bktPolicy); s3Error != ErrNone {
		return s3Error
	}

	// Save bucket policy.
	err = persistAndNotifyBucketPolicyChange(bucket, bktPolicy, objAPI)
	return toAPIErrorCode(err)
}

// persistAndNotifyBucketPolicyChange - takes a policyChange argument,
// persists it to storage, and notify nodes in the cluster about the
// change. In-memory state is updated in response to the notification.
func persistAndNotifyBucketPolicyChange(bucket string, p policy.BucketAccessPolicy, objAPI ObjectLayer) error {
	if len(p.Statements) == 0 {
		return objAPI.DeleteBucketPolicies(bucket)
	}
	if err := objAPI.SetBucketPolicies(bucket, p); err != nil {
		return err
	}

	// Notify all peers (including self) to update in-memory state
	S3PeersUpdateBucketPolicy(bucket, p)
	return nil
}
