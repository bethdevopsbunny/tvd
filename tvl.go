/*


 */
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	log "github.com/sirupsen/logrus"
	"os"
	"strconv"
	tReq "tvl/tenablerequests"
)

var scanHistory tReq.ScanHistory
var alertThresholdList []string
var alertThresholdListInt []int
var VerboseLogging *int
var exitWithError *bool
var scanTimeout int = 100

var ApiKey string

type VulnerabilityCount struct {
	Critical int32
	High     int32
	Medium   int32
	Low      int32
}

/*
VulnerabilityCountOutput Duplication of the Vulnerability Count helps format the output how I wish.
I wanted a simple way to remove results from a struct object at the users request.
This allows a user ignore say low results from the std output not just logging.
it does this by setting the omitempty field on the struct and setting the values of the struct
to omit-able based on the flags provided.
The main reason for it being strings is that for int 0 is an omit field and that's a normal result
for a vulnerability diff program lol.

if i can get a way to remove fields from a struct dynamically this can be removed.

*/
type VulnerabilityCountOutput struct {
	Critical string `json:"Critical,omitempty"`
	High     string `json:"High,omitempty"`
	Medium   string `json:"Medium,omitempty"`
	Low      string `json:"Low,omitempty"`
}

type returnvalue struct {
	VulnerabilityDifference VulnerabilityCountOutput `json:"VulnerabilityDifference"`
	NewVulnerabilities      []tReq.Vulnerability     `json:"NewVulnerabilities"`
}

func init() {

	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	ApiKey = os.Getenv("TENABLE_API_KEY")
	if ApiKey == "" {
		log.Errorf("No api key provided. Please set TENABLE_API_KEY environment variable")
		os.Exit(1)
	}

	// inject tenablerequests package with api key
	tReq.ApiKey = ApiKey
}

func main() {

	// input
	scanTarget := flag.String("scan-name", "asda-stag", "Target scan you wish to compare")
	VerboseLogging = flag.Int("verbose", 0, "Displays Logging")
	critical := flag.Bool("critical", true, "if set to false will omit critical results")
	high := flag.Bool("high", true, "if set to false will omit high results")
	medium := flag.Bool("medium", true, "if set to false will omit medium results")
	low := flag.Bool("low", true, "if set to false will omit low results")
	exitWithError = flag.Bool("exit-with-error", false, "returns errorcode 1 if increase to vulnerabilities")
	noScan := flag.Bool("no-scan", false, "runs diff without triggering a new scan")

	flag.Parse()

	if *scanTarget == "" {
		log.Errorf("Please set --scan argument to compare")
		os.Exit(1)
	}
	if *critical {
		alertThresholdList = append(alertThresholdList, "Critical")
		alertThresholdListInt = append(alertThresholdListInt, 4)
	}
	if *high {
		alertThresholdList = append(alertThresholdList, "High")
		alertThresholdListInt = append(alertThresholdListInt, 3)
	}
	if *medium {
		alertThresholdList = append(alertThresholdList, "Medium")
		alertThresholdListInt = append(alertThresholdListInt, 2)
	}
	if *low {
		alertThresholdList = append(alertThresholdList, "Low")
		alertThresholdListInt = append(alertThresholdListInt, 1)
	}
	if *VerboseLogging > 0 {
		log.Infof("Alerting On: %s", alertThresholdList)
	}

	serverResponse := tReq.GetServerStatus()

	if serverResponse.Code != 200 {
		log.Errorf("Failed to Connect to Tenable api server with serverResponse %s", serverResponse.Status)
		os.Exit(1)
	} else {
		if *VerboseLogging > 0 {
			log.Infof("Connection Succeeded")

		}
	}

	scan, err := tReq.GetScanObject(*scanTarget)
	if err != nil {
		log.Errorf("Failed to retrieve Scan Object")
		os.Exit(1)
	} else {
		if *VerboseLogging > 0 {
			log.Infof("Scan Object Obtained")
		}
	}

	if !*noScan {

		err = tReq.LaunchAndWaitScan(scan, scanTimeout)
		if err != nil {
			log.Errorf("Failed to Launch and Wait")
			os.Exit(1)
		} else {
			if *VerboseLogging > 0 {
				log.Infof("Completed Launch and Wait")
			}
		}

	}

	scanHistory, err = tReq.GetScanHistory(scan.ID)
	if err != nil {
		log.Errorf("Failed to retrieve Scan History")
		os.Exit(1)
	} else {
		if *VerboseLogging > 0 {
			log.Infof("Scan History Obtained")

		}
	}

	scanScope := scansMostRecentAndSort(2, scanHistory.History)

	current, err := tReq.GetScanDetails(scan.ID, scanScope[0].ID)
	if err != nil {
		log.Errorf("Failed to retrieve most recent Scan Details")
		os.Exit(1)
	}

	previous, err := tReq.GetScanDetails(scan.ID, scanScope[1].ID)
	if err != nil {
		log.Errorf("Failed to retrieve previous Scan Details")
		os.Exit(1)
	} else {
		if *VerboseLogging > 0 {
			log.Infof("Scan Details Obtained")

		}
	}

	diffVulnerabilities := diffVulnerabilities(current, previous)

	currentCount := vulnerabilityCounter(current)
	if *VerboseLogging > 1 {
		log.Infof("Current Critical Vulnerabilities %d \n", currentCount.Critical)
		log.Infof("Current High Vulnerabilities %d \n", currentCount.High)
		log.Infof("Current Medium Vulnerabilities %d \n", currentCount.Medium)
		log.Infof("Current Low Vulnerabilities %d \n", currentCount.Low)
	}

	previousCount := vulnerabilityCounter(previous)
	if *VerboseLogging > 1 {
		log.Infof("Previous Critical Vulnerabilities %d \n", previousCount.Critical)
		log.Infof("Previous High Vulnerabilities %d \n", previousCount.High)
		log.Infof("Previous Medium Vulnerabilities %d \n", previousCount.Medium)
		log.Infof("Previous Low Vulnerabilities %d \n", previousCount.Low)
	}

	diffVulnerabilityCount := diffVulnerabilityCounts(currentCount, previousCount)

	LoggingDiff(diffVulnerabilityCount)

	filteredVulnerabilityDifference := alertThresholdFilterVulnerabilityCount(diffVulnerabilityCount)
	filteredDiffVulnerabilities := alertThresholdFilterVulnerabilities(diffVulnerabilities)

	response, err := json.Marshal(
		returnvalue{
			filteredVulnerabilityDifference,
			filteredDiffVulnerabilities,
		},
	)
	if err != nil {
		log.Errorf("Failed to marshal diff count output")
		os.Exit(1)
	}

	fmt.Println(string(response))

}

// vulnerabilityCounter gives you the number of vulnerabilities in a given scan
func vulnerabilityCounter(details tReq.ScanDetails) VulnerabilityCount {

	var returnCount = VulnerabilityCount{}

	for _, v := range details.Vulnerabilities {

		switch v.Severity {
		case 1:
			returnCount.Low++
		case 2:
			returnCount.Medium++
		case 3:
			returnCount.High++
		case 4:
			returnCount.Critical++
		}
	}
	return returnCount
}

//LoggingDiff Qualifies if results in the diff are worth being and asked to be logged.
func LoggingDiff(diffVulnerabilityCount VulnerabilityCount) {

	for _, alertThreshold := range alertThresholdList {

		if alertThreshold == "Critical" && diffVulnerabilityCount.Critical > 0 {
			outLogDiff(alertThreshold)
		}
		if alertThreshold == "High" && diffVulnerabilityCount.High > 0 {
			outLogDiff(alertThreshold)
		}
		if alertThreshold == "Medium" && diffVulnerabilityCount.Medium > 0 {
			outLogDiff(alertThreshold)
		}
		if alertThreshold == "Low" && diffVulnerabilityCount.Low > 0 {
			outLogDiff(alertThreshold)
		}
	}

}

//outLogDiff Displays Desired Output Log with exitWithError
func outLogDiff(alertThreshold string) {
	if *exitWithError {
		log.Errorf("The Script found an increase to %s vulnerabilites\n", alertThreshold)
		os.Exit(1)
	} else {
		log.Warnf("The Script found an increase to %s vulnerabilites\n", alertThreshold)
	}
}

//alertThresholdFilterVulnerabilityCount removes struct fields according to alertThresholdList
func alertThresholdFilterVulnerabilityCount(diffVulnerabilityCount VulnerabilityCount) VulnerabilityCountOutput {

	var strStruct = VulnerabilityCountOutput{
		Critical: formatInt32(diffVulnerabilityCount.Critical),
		High:     formatInt32(diffVulnerabilityCount.High),
		Medium:   formatInt32(diffVulnerabilityCount.Medium),
		Low:      formatInt32(diffVulnerabilityCount.Low),
	}

	switch {
	case !contains(alertThresholdList, "Critical"):
		strStruct.Critical = ""
	case !contains(alertThresholdList, "High"):
		strStruct.High = ""
	case !contains(alertThresholdList, "Medium"):
		strStruct.Medium = ""
	case !contains(alertThresholdList, "Low"):
		strStruct.Low = ""
	}

	return strStruct
}

//alertThresholdFilterVulnerabilities removes slice values according to alertThresholdList
func alertThresholdFilterVulnerabilities(vulnerability []tReq.Vulnerability) []tReq.Vulnerability {

	var returnvulnlist []tReq.Vulnerability

	for _, v := range vulnerability {

		if containsInt(alertThresholdListInt, v.Severity) {
			returnvulnlist = append(returnvulnlist, v)
		}

	}

	return returnvulnlist
}

//	formatInt32 'int32 to string' helper function
func formatInt32(n int32) string {
	return strconv.FormatInt(int64(n), 10)
}

//	contains 'does slice contain' helper function
func contains(s []string, str string) bool {
	for _, v := range s {
		if v == str {
			return true
		}
	}
	return false
}

//	containsInt 'does int slice contain' helper function
func containsInt(s []int, int int) bool {
	for _, v := range s {
		if v == int {
			return true
		}
	}
	return false
}

//	difference 'diff int' helper function
func difference(a, b []int) []int {
	mb := make(map[int]struct{}, len(b))
	for _, x := range b {
		mb[x] = struct{}{}
	}
	var diff []int
	for _, x := range a {
		if _, found := mb[x]; !found {
			diff = append(diff, x)
		}
	}
	return diff
}

// scansMostRecentAndSort returns a slice of the most recent scan history items from provided slice.
// using the count to know how many to return.
func scansMostRecentAndSort(returnSize int, historyItemList []tReq.HistoryItem) []tReq.HistoryItem {

	var mostRecent []tReq.HistoryItem

	for i := 0; i < returnSize; i++ {

		var max = historyItemList[0]

		for _, value := range historyItemList {
			if max.TimeEnd < value.TimeEnd {
				max.TimeEnd = value.TimeEnd
			}

		}

		mostRecent = append(mostRecent, max)

		for i := 0; i < len(historyItemList); i++ {
			if max.ID == historyItemList[i].ID {
				historyItemList = append(historyItemList[:i], historyItemList[i+1:]...)
			}
		}

	}

	return mostRecent

}

//	diffVulnerabilities provides list of Vulnerabilities that were reported in the current scan details object but not in the previous.
// 	Diffs PluginIDs and checks if any unique only occur in current, alluding to an increase.
func diffVulnerabilities(
	currentScanDetails tReq.ScanDetails, previousScanDetails tReq.ScanDetails,
) []tReq.Vulnerability {

	var currentVulnerabilities []int
	var previousVulnerabilities []int

	var returnVulnerabilities []tReq.Vulnerability

	for _, v := range currentScanDetails.Vulnerabilities {
		currentVulnerabilities = append(currentVulnerabilities, v.PluginID)
	}

	for _, v := range previousScanDetails.Vulnerabilities {
		previousVulnerabilities = append(previousVulnerabilities, v.PluginID)
	}

	diffVulnerabilities := difference(currentVulnerabilities, previousVulnerabilities)

	for _, v := range currentScanDetails.Vulnerabilities {

		for _, j := range diffVulnerabilities {

			if j == v.PluginID {
				returnVulnerabilities = append(returnVulnerabilities, v)
			}

		}

	}

	return returnVulnerabilities
}

// diffVulnerabilityCounts deducts the number of current vulnerabilities from the previous.
func diffVulnerabilityCounts(
	currentVulnerabilityCount VulnerabilityCount, previousVulnerabilityCount VulnerabilityCount,
) VulnerabilityCount {

	return VulnerabilityCount{
		Critical: currentVulnerabilityCount.Critical - previousVulnerabilityCount.Critical,
		High:     currentVulnerabilityCount.High - previousVulnerabilityCount.High,
		Medium:   currentVulnerabilityCount.Medium - previousVulnerabilityCount.Medium,
		Low:      currentVulnerabilityCount.Low - previousVulnerabilityCount.Low,
	}

}
