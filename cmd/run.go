package cmd

import (
	"encoding/json"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"os"
	"sort"
	"strconv"
	req "tvd/tenablerequest"
)

var scanHistory req.ScanHistory
var alertThresholdList []string
var alertThresholdListInt []int
var scanTimeout = 100
var alerted = false

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

if I can get a way to remove fields from a struct dynamically this can be removed.

*/
type VulnerabilityCountOutput struct {
	Critical string `json:"Critical,omitempty"`
	High     string `json:"High,omitempty"`
	Medium   string `json:"Medium,omitempty"`
	Low      string `json:"Low,omitempty"`
}

type returnValue struct {
	VulnerabilityDifference VulnerabilityCountOutput `json:"VulnerabilityDifference"`
	NewVulnerabilities      []req.Vulnerability      `json:"NewVulnerabilities"`
}

func init() {

	log.SetLevel(log.InfoLevel)
	log.SetFormatter(&log.TextFormatter{FullTimestamp: true})

	//remove help shorthand due to clash with high
	runCmd.PersistentFlags().BoolP("help", "", false, "help for this command")

	runCmd.PersistentFlags().StringVarP(&scanTarget, "scan-name", "s", "", "target scan you wish to compare")
	runCmd.PersistentFlags().BoolVarP(&critical, "critical", "c", true, "if set to false will omit critical results")
	runCmd.PersistentFlags().BoolVarP(&high, "high", "h", true, "if set to false will omit high results")
	runCmd.PersistentFlags().BoolVarP(&medium, "medium", "m", true, "if set to false will omit medium results")
	runCmd.PersistentFlags().BoolVarP(&low, "low", "l", true, "if set to false will omit low results")
	runCmd.PersistentFlags().BoolVarP(&exitWithError, "exit-with-error", "e", false, "returns error code 1 if increase to vulnerabilities")
	runCmd.PersistentFlags().BoolVarP(&noScan, "no-scan", "n", false, "runs the diff without triggering a new scan")
	runCmd.PersistentFlags().IntVarP(&VerboseLogging, "verbose", "v", 0, "Displays Logging")
	runCmd.PersistentFlags().IntVarP(&top, "top", "t", 30, "clamp the number of vulnerabilities returned in NewVulnerabilities")

	rootCmd.AddCommand(runCmd)

}

var (
	scanTarget     string
	critical       bool
	high           bool
	medium         bool
	low            bool
	exitWithError  bool
	noScan         bool
	VerboseLogging int
	top            int
)

var runCmd = &cobra.Command{

	Use:   "run",
	Short: "starts vulnerability diff",
	Long: `
run launches a new scan on tenable.io, upon completion it grabs scan history data and compares
the last two scans for any changes in vulnerabilities
with "-c, -h, -m, -l" you can tailor alerts/results and exit with error with "-e"
returns json object with count difference and list of vulnerabilities listed in the most recent scan`,

	Run: func(cmd *cobra.Command, args []string) {

		authentication()

		if scanTarget == "" {
			log.Errorf("Please set --scan argument to compare")
			os.Exit(1)
		}
		if critical {
			alertThresholdList = append(alertThresholdList, "Critical")
			alertThresholdListInt = append(alertThresholdListInt, 4)
		}
		if high {
			alertThresholdList = append(alertThresholdList, "High")
			alertThresholdListInt = append(alertThresholdListInt, 3)
		}
		if medium {
			alertThresholdList = append(alertThresholdList, "Medium")
			alertThresholdListInt = append(alertThresholdListInt, 2)
		}
		if low {
			alertThresholdList = append(alertThresholdList, "Low")
			alertThresholdListInt = append(alertThresholdListInt, 1)
		}
		if VerboseLogging > 0 {
			log.Infof("Alerting On: %s", alertThresholdList)
		}

		serverResponse := req.GetServerStatus()

		if serverResponse.Code != 200 {
			log.Errorf(
				"Failed to Connect to Tenable api server with serverResponse %s", serverResponse.Status,
			)
			os.Exit(1)
		} else {
			if VerboseLogging > 0 {
				log.Infof("Connection Succeeded")

			}
		}

		scan, err := req.GetScanObject(scanTarget)
		if err != nil {
			log.Errorf("Failed to retrieve Scan Object")
			os.Exit(1)
		} else {
			if VerboseLogging > 0 {
				log.Infof("Scan Object Obtained")
			}
		}

		if !noScan {

			err = req.LaunchAndWaitScan(scan, scanTimeout)
			if err != nil {
				log.Errorf("Failed to Launch and Wait")
				os.Exit(1)
			} else {
				if VerboseLogging > 0 {
					log.Infof("Completed Launch and Wait")
				}
			}

		}

		scanHistory, err = req.GetScanHistory(scan.ID)
		if err != nil {
			log.Errorf("Failed to retrieve Scan History")
			os.Exit(1)
		} else {
			if VerboseLogging > 0 {
				log.Infof("Scan History Obtained")

			}
		}

		scanScope := scansMostRecentAndSort(2, scanHistory.History)

		current, err := req.GetScanDetails(scan.ID, scanScope[0].ID)
		if err != nil {
			log.Errorf("Failed to retrieve most recent Scan Details")
			os.Exit(1)
		}

		previous, err := req.GetScanDetails(scan.ID, scanScope[1].ID)
		if err != nil {
			log.Errorf("Failed to retrieve previous Scan Details")
			os.Exit(1)
		} else {
			if VerboseLogging > 0 {
				log.Infof("Scan Details Obtained")

			}
		}

		diffVulnerabilities := diffVulnerabilities(current, previous)

		currentCount := vulnerabilityCounter(current)
		if VerboseLogging > 1 {
			log.Infof("Current Critical Vulnerabilities %d \n", currentCount.Critical)
			log.Infof("Current High Vulnerabilities %d \n", currentCount.High)
			log.Infof("Current Medium Vulnerabilities %d \n", currentCount.Medium)
			log.Infof("Current Low Vulnerabilities %d \n", currentCount.Low)
		}

		previousCount := vulnerabilityCounter(previous)
		if VerboseLogging > 1 {
			log.Infof("Previous Critical Vulnerabilities %d \n", previousCount.Critical)
			log.Infof("Previous High Vulnerabilities %d \n", previousCount.High)
			log.Infof("Previous Medium Vulnerabilities %d \n", previousCount.Medium)
			log.Infof("Previous Low Vulnerabilities %d \n", previousCount.Low)
		}

		diffVulnerabilityCount := diffVulnerabilityCounts(currentCount, previousCount)

		filteredVulnerabilityDifference := alertThresholdFilterVulnerabilityCount(diffVulnerabilityCount)
		filteredDiffVulnerabilities := alertThresholdFilterVulnerabilities(diffVulnerabilities)
		filteredDiffVulnerabilities = sortVulnerabilities(filteredDiffVulnerabilities)

		if len(filteredDiffVulnerabilities) > top {
			filteredDiffVulnerabilities = filteredDiffVulnerabilities[:top]
		}

		response, err := json.Marshal(
			returnValue{
				filteredVulnerabilityDifference,
				filteredDiffVulnerabilities,
			},
		)
		if err != nil {
			log.Errorf("Failed to marshal diff count output")
			os.Exit(1)
		}
		doesItDiff(diffVulnerabilityCount)
		fmt.Println(string(response))
		if exitWithError && alerted {
			os.Exit(1)
		}
	},
}

func authentication() {

	ApiKey = os.Getenv("TENABLE_API_KEY")
	if ApiKey == "" {
		log.Errorf("No api key provided. Please set TENABLE_API_KEY environment variable")
		os.Exit(1)
	}

	// inject tenablerequest package with api key
	req.ApiKey = ApiKey

}

// vulnerabilityCounter gives you the number of vulnerabilities in a given scan
func vulnerabilityCounter(details req.ScanDetails) VulnerabilityCount {

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

func sortVulnerabilities(vulnerabilities []req.Vulnerability) []req.Vulnerability {

	sort.Slice(
		vulnerabilities, func(i, j int) bool {
			return vulnerabilities[i].Severity > vulnerabilities[j].Severity
		},
	)
	return vulnerabilities
}

//doesItDiff Qualifies if there are diffs in the diff and if the user wants them alerted.
func doesItDiff(diffVulnerabilityCount VulnerabilityCount) {

	for _, alertThreshold := range alertThresholdList {

		if alertThreshold == "Critical" && diffVulnerabilityCount.Critical > 0 {
			alerted = true
			outLogDiff(alertThreshold)
		}
		if alertThreshold == "High" && diffVulnerabilityCount.High > 0 {
			alerted = true
			outLogDiff(alertThreshold)
		}
		if alertThreshold == "Medium" && diffVulnerabilityCount.Medium > 0 {
			alerted = true
			outLogDiff(alertThreshold)
		}
		if alertThreshold == "Low" && diffVulnerabilityCount.Low > 0 {
			alerted = true
			outLogDiff(alertThreshold)
		}
	}
}

//outLogDiff Displays Desired Output Log with exitWithError
func outLogDiff(alertThreshold string) {
	if exitWithError {
		log.Errorf("The Script found an increase to %s vulnerabilities\n", alertThreshold)
	} else {
		log.Warnf("The Script found an increase to %s vulnerabilities\n", alertThreshold)
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

	// switch statements auto break and don't have a non break option?
	// what a crazy world.
	if !contains(alertThresholdList, "Critical") {
		strStruct.Critical = ""
	}
	if !contains(alertThresholdList, "High") {
		strStruct.High = ""
	}
	if !contains(alertThresholdList, "Medium") {
		strStruct.Medium = ""
	}
	if !contains(alertThresholdList, "Low") {
		strStruct.Low = ""
	}

	return strStruct
}

//alertThresholdFilterVulnerabilities removes slice values according to alertThresholdList
func alertThresholdFilterVulnerabilities(vulnerability []req.Vulnerability) []req.Vulnerability {

	var returnVulnerabilitiesList []req.Vulnerability

	for _, v := range vulnerability {

		if containsInt(alertThresholdListInt, v.Severity) {
			returnVulnerabilitiesList = append(returnVulnerabilitiesList, v)
		}

	}

	return returnVulnerabilitiesList
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
func scansMostRecentAndSort(returnSize int, historyItemList []req.HistoryItem) []req.HistoryItem {

	var mostRecent []req.HistoryItem

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
	currentScanDetails req.ScanDetails, previousScanDetails req.ScanDetails,
) []req.Vulnerability {

	var currentVulnerabilities []int
	var previousVulnerabilities []int

	var returnVulnerabilities []req.Vulnerability

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
