package tenablerequest

import (
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
)

type Scan struct {
	Control              bool   `json:"control"`
	CreationDate         int    `json:"creation_date"`
	Enabled              bool   `json:"enabled"`
	ID                   int    `json:"id"`
	LastModificationDate int    `json:"last_modification_date"`
	Legacy               bool   `json:"legacy"`
	Name                 string `json:"name"`
	Owner                string `json:"owner"`
	PolicyID             int    `json:"policy_id"`
	Read                 bool   `json:"read"`
	Rrules               string `json:"rrules,omitempty"`
	ScheduleUUID         string `json:"schedule_uuid"`
	Shared               bool   `json:"shared"`
	Starttime            string `json:"starttime,omitempty"`
	Status               string `json:"status"`
	TemplateUUID         string `json:"template_uuid,omitempty"`
	Timezone             string `json:"timezone,omitempty"`
	HasTriggers          bool   `json:"has_triggers"`
	Type                 string `json:"type,omitempty"`
	Permissions          int    `json:"permissions"`
	UserPermissions      int    `json:"user_permissions"`
	UUID                 string `json:"uuid,omitempty"`
	WizardUUID           string `json:"wizard_uuid"`
	Progress             int    `json:"progress,omitempty"`
}

type Folder struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Type        string `json:"type"`
	Custom      int    `json:"custom"`
	UnreadCount int    `json:"unread_count"`
	DefaultTag  int    `json:"default_tag"`
}

type ScanList struct {
	Scans     []Scan   `json:"scans"`
	Folders   []Folder `json:"folders"`
	Timestamp int      `json:"timestamp"`
}

func GetScanObject(scanName string) (Scan, error) {
	var scans ScanList
	url := "https://cloud.tenable.com/scans"

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return Scan{}, err
	}
	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-ApiKeys", ApiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return Scan{}, err
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return Scan{}, err
	}

	err = json.Unmarshal(body, &scans)
	if err != nil {
		return Scan{}, err
	}

	allScans := &scans

	for i := 0; i < len(allScans.Scans); i++ {

		if allScans.Scans[i].Name == scanName {
			return allScans.Scans[i], nil
		}

	}

	return Scan{}, errors.New("failed to get scan object")
}
