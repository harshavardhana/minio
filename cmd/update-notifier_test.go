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
		t1             time.Time
		t2             time.Time
		expectedResult string
	}{
		{UTCNow(), UTCNow().Add(1 * time.Second), "a second old"},
		{UTCNow(), UTCNow().Add(1 * time.Minute), "a minute old"},
		{UTCNow(), UTCNow().Add(1 * time.Hour), "an hour old"},
		{UTCNow(), UTCNow().Add(24 * time.Hour), "a day old"},
		{UTCNow(), UTCNow().Add(2 * time.Second), "2 seconds old"},
		{UTCNow(), UTCNow().Add(2 * time.Minute), "2 minutes old"},
		{UTCNow(), UTCNow().Add(2 * time.Hour), "2 hours old"},
		{UTCNow(), UTCNow().Add(48 * time.Hour), "2 days old"},
		{UTCNow(), UTCNow().Add(48*time.Hour + 17*time.Hour + 3*time.Minute + 10*time.Second), "2 days old"},
		{UTCNow(), UTCNow().Add(48*time.Hour + 3*time.Minute), "2 days old"},
		{UTCNow(), UTCNow().Add(7*time.Hour + 3*time.Minute), "7 hours old"},
		{UTCNow(), UTCNow().Add(3*time.Minute + 43*time.Second), "3 minutes old"},
		{UTCNow(), UTCNow().Add(43*time.Second + time.Duration(7762)), "43 seconds old"},
		{UTCNow(), UTCNow().Add(time.Duration(7762)), "now"},
	}

	for _, testCase := range testCases {
		durationStr := humanizeDuration(testCase.t1, testCase.t2)
		if durationStr != testCase.expectedResult {
			t.Fatalf("expected: %v, got: %v", testCase.expectedResult, durationStr)
		}
	}
}

// Tests update notifier string builder.
func TestUpdateNotifier(t *testing.T) {
	tnow := UTCNow()
	colorUpdateMsg := colorizeUpdateMessage(minioReleaseURL, humanizeDuration(tnow.Add(72*time.Hour), tnow))
	if !strings.Contains(colorUpdateMsg, "3 days") {
		t.Fatal("Duration string not found in colorized update message", colorUpdateMsg)
	}
	if !strings.Contains(colorUpdateMsg, minioReleaseURL) {
		t.Fatal("Update message not found in colorized update message", minioReleaseURL)
	}
}
