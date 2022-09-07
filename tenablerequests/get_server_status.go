package tenablerequests

import (
	"net/http"
)

type ServerStatus struct {
	Code   int    `json:"code"`
	Status string `json:"status"`
}

func GetServerStatus() ServerStatus {

	url := "https://cloud.tenable.com/scans"

	req, _ := http.NewRequest("GET", url, nil)

	req.Header.Add("Accept", "application/json")

	req.Header.Add("X-ApiKeys", ApiKey)

	res, _ := http.DefaultClient.Do(req)

	defer res.Body.Close()

	return ServerStatus{Code: res.StatusCode, Status: res.Status}

}
