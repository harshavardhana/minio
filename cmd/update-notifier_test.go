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

package cmd

import (
	"strings"
	"testing"
	"time"
)

func TestHumanizeDuration(t *testing.T) {
	testCases := []struct {
		duration       time.Duration
		expectedResult string
	}{
		{1 * time.Second, "a second"},
		{1 * time.Minute, "a minute"},
		{1 * time.Hour, "an hour"},
		{24 * time.Hour, "a day"},
		{2 * time.Second, "2 seconds"},
		{2 * time.Minute, "2 minutes"},
		{2 * time.Hour, "2 hours"},
		{48 * time.Hour, "2 days"},
		{48*time.Hour + 17*time.Hour + 3*time.Minute + 10*time.Second, "2 days"},
		{48*time.Hour + 3*time.Minute, "2 days"},
		{7*time.Hour + 3*time.Minute, "7 hours"},
		{3*time.Minute + 43*time.Second, "3 minutes"},
		{43*time.Second + time.Duration(7762), "43 seconds"},
		{time.Duration(7762), "just"},
	}

	for _, testCase := range testCases {
		durationStr := humanizeDuration(testCase.duration)
		if durationStr != testCase.expectedResult {
			t.Fatalf("expected: %v, got: %v", testCase.expectedResult, durationStr)
		}
	}
}

// Tests update notifier string builder.
func TestUpdateNotifier(t *testing.T) {
	colorUpdateMsg := colorizeUpdateMessage(minioReleaseURL, time.Duration(72*time.Hour))
	if !strings.Contains(colorUpdateMsg, "3 days") {
		t.Fatal("Duration string not found in colorized update message", colorUpdateMsg)
	}
	if !strings.Contains(colorUpdateMsg, minioReleaseURL) {
		t.Fatal("Update message not found in colorized update message", minioReleaseURL)
	}
}
