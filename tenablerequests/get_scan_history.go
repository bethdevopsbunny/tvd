package tenablerequests

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type ScanHistory struct {
	Pagination struct {
		Offset int `json:"offset"`
		Total  int `json:"total"`
		Sort   []struct {
			Order string `json:"order"`
			Name  string `json:"name"`
		} `json:"sort"`
		Limit int `json:"limit"`
	} `json:"pagination"`
	History []HistoryItem `json:"history"`
}

type HistoryItem struct {
	ID         int    `json:"id"`
	Status     string `json:"status"`
	IsArchived bool   `json:"is_archived"`
	Targets    struct {
		Custom  bool        `json:"custom"`
		Default interface{} `json:"default"`
	} `json:"targets"`
	Visibility string      `json:"visibility"`
	ScanUUID   string      `json:"scan_uuid"`
	Reindexing interface{} `json:"reindexing"`
	TimeStart  int         `json:"time_start"`
	TimeEnd    int         `json:"time_end"`
}

func GetScanHistory(id int) (ScanHistory, error) {

	url := fmt.Sprintf("https://cloud.tenable.com/scans/%d/history", id)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ScanHistory{}, err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-ApiKeys", ApiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return ScanHistory{}, err
	}

	defer res.Body.Close()
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return ScanHistory{}, err
	}

	var scanHistory ScanHistory
	err = json.Unmarshal(body, &scanHistory)
	if err != nil {
		return ScanHistory{}, err
	}

	return scanHistory, nil

}
