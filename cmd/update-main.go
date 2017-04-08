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
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	humanize "github.com/dustin/go-humanize"
	"github.com/fatih/color"
	"github.com/minio/cli"
)

// Check for new software updates.
var updateCmd = cli.Command{
	Name:   "update",
	Usage:  "Check for a new software update.",
	Action: mainUpdate,
	Flags: []cli.Flag{
		cli.BoolFlag{
			Name:  "quiet",
			Usage: "Disable any update messages.",
		},
	},
	CustomHelpTemplate: `Name:
   {{.HelpName}} - {{.Usage}}

USAGE:
   {{.HelpName}}{{if .VisibleFlags}} [FLAGS]{{end}}
{{if .VisibleFlags}}
FLAGS:
  {{range .VisibleFlags}}{{.}}
  {{end}}{{end}}
EXIT STATUS:
   0 - You are already running the most recent version.
   1 - New update is available.
  -1 - Error in getting update information.

EXAMPLES:
   1. Check if there is a new update available:
       $ {{.HelpName}}
`,
}

const (
	minioReleaseTagTimeLayout = "2006-01-02T15-04-05Z"
	minioReleaseURL           = "https://dl.minio.io/server/minio/release/" + runtime.GOOS + "-" + runtime.GOARCH + "/"
)

func getCurrentReleaseTime(minioVersion, minioBinaryPath string) (releaseTime time.Time, err error) {
	if releaseTime, err = time.Parse(time.RFC3339, minioVersion); err == nil {
		return releaseTime, err
	}

	if !filepath.IsAbs(minioBinaryPath) {
		// Make sure to look for the absolute path of the binary.
		minioBinaryPath, err = exec.LookPath(minioBinaryPath)
		if err != nil {
			return releaseTime, err
		}
	}

	// Looks like version is minio non-standard, we use minio binary's ModTime as release time.
	fi, err := os.Stat(minioBinaryPath)
	if err != nil {
		err = fmt.Errorf("Unable to get ModTime of %s. %s", minioBinaryPath, err)
	} else {
		releaseTime = fi.ModTime().UTC()
	}

	return releaseTime, err
}

// GetCurrentReleaseTime - returns this process's release time.  If it is official minio version,
// parsed version is returned else minio binary's mod time is returned.
func GetCurrentReleaseTime() (releaseTime time.Time, err error) {
	return getCurrentReleaseTime(Version, os.Args[0])
}

func isDocker(cgroupFile string) (bool, error) {
	cgroup, err := ioutil.ReadFile(cgroupFile)
	if os.IsNotExist(err) {
		err = nil
	}

	return bytes.Contains(cgroup, []byte("docker")), err
}

// IsDocker - returns if the environment is docker or not.
func IsDocker() bool {
	found, err := isDocker("/proc/self/cgroup")
	fatalIf(err, "Error in docker check.")

	return found
}

func isSourceBuild(minioVersion string) bool {
	_, err := time.Parse(time.RFC3339, minioVersion)
	return err != nil
}

// IsSourceBuild - returns if this binary is made from source or not.
func IsSourceBuild() bool {
	return isSourceBuild(Version)
}

// DO NOT CHANGE USER AGENT STYLE.
// The style should be
//   Minio (<OS>; <ARCH>[; docker][; source])  Minio/<VERSION> Minio/<RELEASE-TAG> Minio/<COMMIT-ID>
//
// For any change here should be discussed by openning an issue at https://github.com/minio/minio/issues.
func getUserAgent(mode string) string {
	userAgent := "Minio (" + runtime.GOOS + "; " + runtime.GOARCH
	if mode != "" {
		userAgent += "; " + mode
	}
	if IsDocker() {
		userAgent += "; docker"
	}
	if IsSourceBuild() {
		userAgent += "; source"
	}
	userAgent += ") " + " Minio/" + Version + " Minio/" + ReleaseTag + " Minio/" + CommitID

	return userAgent
}

func downloadReleaseData(releaseChecksumURL string, timeout time.Duration, mode string) (data string, err error) {
	req, err := http.NewRequest("GET", releaseChecksumURL, nil)
	if err != nil {
		return data, err
	}
	req.Header.Set("User-Agent", getUserAgent(mode))

	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			// need to close connection after usage.
			DisableKeepAlives: true,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return data, err
	}
	if resp == nil {
		return data, fmt.Errorf("No response from server to download URL %s", releaseChecksumURL)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return data, fmt.Errorf("Error downloading URL %s. Response: %v", releaseChecksumURL, resp.Status)
	}

	dataBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return data, fmt.Errorf("Error reading response. %s", err)
	}

	data = string(dataBytes)
	return data, err
}

// DownloadReleaseData - downloads release data from minio official server.
func DownloadReleaseData(timeout time.Duration, mode string) (data string, err error) {
	return downloadReleaseData(minioReleaseURL+"minio.shasum", timeout, mode)
}

func parseReleaseData(data string) (releaseTime time.Time, err error) {
	fields := strings.Fields(data)
	if len(fields) != 2 {
		err = fmt.Errorf("Unknown release data `%s`", data)
		return releaseTime, err
	}

	releaseInfo := fields[1]
	if fields = strings.Split(releaseInfo, "."); len(fields) != 3 {
		err = fmt.Errorf("Unknown release information `%s`", releaseInfo)
		return releaseTime, err
	}

	if !(fields[0] == "minio" && fields[1] == "RELEASE") {
		err = fmt.Errorf("Unknown release '%s'", releaseInfo)
		return releaseTime, err
	}

	releaseTime, err = time.Parse(minioReleaseTagTimeLayout, fields[2])
	if err != nil {
		err = fmt.Errorf("Unknown release time format. %s", err)
	}

	return releaseTime, err
}

func getLatestReleaseTime(timeout time.Duration, mode string) (releaseTime time.Time, err error) {
	data, err := DownloadReleaseData(timeout, mode)
	if err != nil {
		return releaseTime, err
	}

	return parseReleaseData(data)
}

func getDownloadURL() (downloadURL string) {
	if IsDocker() {
		return "docker pull minio/minio"
	}

	if runtime.GOOS == "windows" {
		return minioReleaseURL + "minio.exe"
	}

	return minioReleaseURL + "minio"
}

// humanizeDuration converts time.Duration to human readable duration.
func humanizeDuration(then, now time.Time) (durationStr string) {
	var defaultMagnitudes = []humanize.RelTimeMagnitude{
		{time.Second, "now", time.Second},
		{2 * time.Second, "a second %s", 1},
		{time.Minute, "%d seconds %s", time.Second},
		{2 * time.Minute, "a minute %s", 1},
		{time.Hour, "%d minutes %s", time.Minute},
		{2 * time.Hour, "an hour %s", 1},
		{humanize.Day, "%d hours %s", time.Hour},
		{2 * humanize.Day, "a day %s", 1},
		{humanize.Week, "%d days %s", humanize.Day},
		{2 * humanize.Week, "a week %s", 1},
		{humanize.Month, "%d weeks %s", humanize.Week},
		{2 * humanize.Month, "a month %s", 1},
		{humanize.Year, "%d months %s", humanize.Month},
		{18 * humanize.Month, "an year %s", 1},
		{2 * humanize.Year, "2 years %s", 1},
		{humanize.LongTime, "%d years %s", humanize.Year},
		{math.MaxInt64, "a long while %s", 1},
	}
	return humanize.CustomRelTime(then, now, "old", "new", defaultMagnitudes)
}

func getUpdateInfo(timeout time.Duration, mode string) (durationStr string, downloadURL string, err error) {
	currentReleaseTime, err := GetCurrentReleaseTime()
	if err != nil {
		return durationStr, downloadURL, err
	}

	latestReleaseTime, err := getLatestReleaseTime(timeout, mode)
	if err != nil {
		return durationStr, downloadURL, err
	}

	if latestReleaseTime.After(currentReleaseTime) {
		durationStr = humanizeDuration(latestReleaseTime, currentReleaseTime)
		downloadURL = getDownloadURL()
	}
	return durationStr, downloadURL, nil
}

func mainUpdate(ctx *cli.Context) {
	if len(ctx.Args()) != 0 {
		cli.ShowCommandHelpAndExit(ctx, "update", -1)
	}

	quiet := ctx.Bool("quiet") || ctx.GlobalBool("quiet")
	if quiet {
		log.EnableQuiet()
	}

	minioMode := ""
	durationStr, downloadURL, err := getUpdateInfo(10*time.Second, minioMode)
	if err != nil {
		log.Println(err)
		os.Exit(-1)
	}

	if durationStr != "" {
		log.Println(colorizeUpdateMessage(downloadURL, durationStr))
		os.Exit(1)
	}

	colorSprintf := color.New(color.FgGreen, color.Bold).SprintfFunc()
	log.Println(colorSprintf("You are already running the most recent version of ‘minio’."))
	os.Exit(0)
}
