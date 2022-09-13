package tenablerequest

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type ScanStatus struct {
	Status   string `json:"status"`
	Progress int    `json:"progress"`
}

func GetScanStatus(id int) (ScanStatus, error) {

	url := fmt.Sprintf("https://cloud.tenable.com/scans/%d/latest-status", id)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ScanStatus{}, err
	}

	req.Header.Add("Accept", "application/json")

	req.Header.Add("X-ApiKeys", ApiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return ScanStatus{}, err
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return ScanStatus{}, err
	}

	var scanStatus ScanStatus
	err = json.Unmarshal(body, &scanStatus)
	if err != nil {
		return ScanStatus{}, err
	}

	return scanStatus, nil

}
