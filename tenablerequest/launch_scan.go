package tenablerequest

import (
	"fmt"
	log "github.com/sirupsen/logrus"
	"io/ioutil"
	"net/http"
	"time"
)

func Launch(id int) error {

	url := fmt.Sprintf("https://cloud.tenable.com/scans/%d/launch", id)

	req, err := http.NewRequest("POST", url, nil)
	if err != nil {
		return err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("X-ApiKeys", ApiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}

	defer res.Body.Close()

	_, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return err
	}

	return nil

}

//LaunchAndWaitScan initiated new scan and waits for it to complete before completing
func LaunchAndWaitScan(scan Scan, scanTimeout int) error {

	err := Launch(scan.ID)
	if err != nil {
		return err
	}

	// Waiting
	i := 0
	for {
		currentStatus, _ := GetScanStatus(scan.ID)
		log.Infof("Scan Status: %s \n", currentStatus.Status)
		i++
		if currentStatus.Progress >= 100 || i >= scanTimeout {
			break
		}

		time.Sleep(1 * time.Minute)
	}

	return nil

}
