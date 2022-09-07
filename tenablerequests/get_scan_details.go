package tenablerequests

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
)

type ScanDetails struct {
	Info struct {
		Owner           string      `json:"owner"`
		Name            string      `json:"name"`
		NoTarget        bool        `json:"no_target"`
		FolderID        int         `json:"folder_id"`
		Control         bool        `json:"control"`
		UserPermissions int         `json:"user_permissions"`
		ScheduleUUID    string      `json:"schedule_uuid"`
		EditAllowed     bool        `json:"edit_allowed"`
		ScannerName     string      `json:"scanner_name"`
		Policy          string      `json:"policy"`
		Shared          bool        `json:"shared"`
		ObjectID        interface{} `json:"object_id"`
		TagTargets      interface{} `json:"tag_targets"`
		Acls            interface{} `json:"acls"`
		Hostcount       int         `json:"hostcount"`
		UUID            string      `json:"uuid"`
		Status          string      `json:"status"`
		ScanType        string      `json:"scan_type"`
		Targets         string      `json:"targets"`
		AltTargetsUsed  bool        `json:"alt_targets_used"`
		PciCanUpload    bool        `json:"pci-can-upload"`
		ScanStart       int         `json:"scan_start"`
		Timestamp       int         `json:"timestamp"`
		IsArchived      bool        `json:"is_archived"`
		Reindexing      bool        `json:"reindexing"`
		ScanEnd         int         `json:"scan_end"`
		Haskb           bool        `json:"haskb"`
		Hasaudittrail   bool        `json:"hasaudittrail"`
		ScannerStart    interface{} `json:"scanner_start"`
		ScannerEnd      interface{} `json:"scanner_end"`
	} `json:"info"`
	// removed plural from return object as this is intended to run for scans with 1 host object. and it looks cleaner this way .
	Hosts           []Host `json:"hosts"`
	Vulnerabilities []struct {
		Count        int    `json:"count"`
		PluginID     int    `json:"plugin_id"`
		PluginName   string `json:"plugin_name"`
		Severity     int    `json:"severity"`
		PluginFamily string `json:"plugin_family"`
		VulnIndex    int    `json:"vuln_index"`
	} `json:"vulnerabilities"`
	Comphosts  []interface{} `json:"comphosts"`
	Compliance []interface{} `json:"compliance"`
	Filters    []struct {
		Name         string `json:"name"`
		ReadableName string `json:"readable_name"`
		Control      struct {
			Type          string `json:"type"`
			Regex         string `json:"regex"`
			ReadableRegex string `json:"readable_regex"`
		} `json:"control,omitempty"`
		Operators []string `json:"operators"`
		GroupName string   `json:"group_name"`
		Control0  struct {
			Type          string `json:"type"`
			Regex         string `json:"regex"`
			ReadableRegex string `json:"readable_regex"`
			Maxlength     int    `json:"maxlength"`
		} `json:"control,omitempty"`
		Control1 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control2 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control3 struct {
			Type          string `json:"type"`
			Regex         string `json:"regex"`
			ReadableRegex string `json:"readable_regex"`
			Maxlength     int    `json:"maxlength"`
		} `json:"control,omitempty"`
		Control4 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control5 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control6 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control7 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control8 struct {
			Type          string `json:"type"`
			Regex         string `json:"regex"`
			ReadableRegex string `json:"readable_regex"`
			Maxlength     int    `json:"maxlength"`
		} `json:"control,omitempty"`
		Control9 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control10 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control11 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control12 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control13 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control14 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control15 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control16 struct {
			Type          string `json:"type"`
			Regex         string `json:"regex"`
			ReadableRegex string `json:"readable_regex"`
			Maxlength     int    `json:"maxlength"`
		} `json:"control,omitempty"`
		Control17 struct {
			Type string `json:"type"`
			List []struct {
				Name string `json:"name"`
				ID   int    `json:"id"`
			} `json:"list"`
		} `json:"control,omitempty"`
		Control18 struct {
			Type          string `json:"type"`
			Regex         string `json:"regex"`
			ReadableRegex string `json:"readable_regex"`
			Maxlength     int    `json:"maxlength"`
		} `json:"control,omitempty"`
		Control19 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control20 struct {
			Type          string `json:"type"`
			Regex         string `json:"regex"`
			ReadableRegex string `json:"readable_regex"`
			Maxlength     int    `json:"maxlength"`
		} `json:"control,omitempty"`
		Control21 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control22 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control23 struct {
			Type          string `json:"type"`
			Regex         string `json:"regex"`
			ReadableRegex string `json:"readable_regex"`
			Maxlength     int    `json:"maxlength"`
		} `json:"control,omitempty"`
		Control24 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		Control25 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
		CustomControl []struct {
			CstmOpr   string `json:"cstmOpr"`
			CstmCntrl struct {
				Type          string `json:"type"`
				Regex         string `json:"regex"`
				ReadableRegex string `json:"readable_regex"`
				Maxlength     int    `json:"maxlength"`
			} `json:"cstmCntrl"`
		} `json:"customControl,omitempty"`
		Control26 struct {
			Type string   `json:"type"`
			List []string `json:"list"`
		} `json:"control,omitempty"`
	} `json:"filters"`
	History []struct {
		HistoryID            int    `json:"history_id"`
		OwnerID              int    `json:"owner_id"`
		CreationDate         int    `json:"creation_date"`
		LastModificationDate int    `json:"last_modification_date"`
		UUID                 string `json:"uuid"`
		Type                 string `json:"type"`
		Status               string `json:"status"`
		Scheduler            int    `json:"scheduler"`
		AltTargetsUsed       bool   `json:"alt_targets_used"`
		IsArchived           bool   `json:"is_archived"`
	} `json:"history"`
	Notes        []interface{} `json:"notes"`
	Remediations struct {
		NumCves           int           `json:"num_cves"`
		NumHosts          int           `json:"num_hosts"`
		NumRemediatedCves int           `json:"num_remediated_cves"`
		NumImpactedHosts  int           `json:"num_impacted_hosts"`
		Remediations      []interface{} `json:"remediations"`
	} `json:"remediations"`
}

type Host struct {
	AssetID               int    `json:"asset_id"`
	HostID                int    `json:"host_id"`
	UUID                  string `json:"uuid"`
	Hostname              string `json:"hostname"`
	Progress              string `json:"progress"`
	Scanprogresscurrent   int    `json:"scanprogresscurrent"`
	Scanprogresstotal     int    `json:"scanprogresstotal"`
	Numchecksconsidered   int    `json:"numchecksconsidered"`
	Totalchecksconsidered int    `json:"totalchecksconsidered"`
	Severitycount         struct {
		Item []struct {
			Count         int `json:"count"`
			Severitylevel int `json:"severitylevel"`
		} `json:"item"`
	} `json:"severitycount"`
	Severity  int `json:"severity"`
	Score     int `json:"score"`
	Info      int `json:"info"`
	Low       int `json:"low"`
	Medium    int `json:"medium"`
	High      int `json:"high"`
	Critical  int `json:"critical"`
	HostIndex int `json:"host_index"`
}

func GetScanDetails(scanID int, historyID int) (ScanDetails, error) {

	var scanDetails ScanDetails
	url := fmt.Sprintf("https://cloud.tenable.com/scans/%d?history_id=%d", scanID, historyID)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return ScanDetails{}, err
	}

	req.Header.Add("Accept", "application/json")
	req.Header.Add("X-ApiKeys", ApiKey)

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return ScanDetails{}, err
	}

	defer res.Body.Close()

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return ScanDetails{}, err
	}

	err = json.Unmarshal(body, &scanDetails)
	if err != nil {
		return ScanDetails{}, err
	}

	return scanDetails, nil
}
