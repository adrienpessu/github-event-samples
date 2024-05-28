package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gocarina/gocsv"
	"github.com/joho/godotenv"
)

func main() {

	err := godotenv.Load()
	if err != nil {
		panic("Error loading .env file")
	}

	githubToken := os.Getenv("GITHUB_TOKEN")
	githubOrganization := os.Getenv("GITHUB_ORGANIZATION")

	// Get Code Scanning Alerts
	var CodeScanningAlertRestsContainer []CodeScanningAlertRest
	alerts := getCodeScanningAlertRests(githubToken, githubOrganization, CodeScanningAlertRestsContainer, 1)

	// Convert JSON to CSV
	file, err := os.OpenFile("code_scanning.csv", os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	gocsv.MarshalCSV(alerts, gocsv.DefaultCSVWriter(file))

	// Get Secret Scanning Alerts
	var SecretScanningAlertRestsContainer []SecretScanningAlertRest
	secretAlerts := getSecretScanningAlertRests(githubToken, githubOrganization, SecretScanningAlertRestsContainer, 1)

	// Convert JSON to CSV
	secretFile, err := os.OpenFile("secret_scanning.csv", os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		panic(err)
	}
	defer secretFile.Close()
	gocsv.MarshalCSV(secretAlerts, gocsv.DefaultCSVWriter(secretFile))

	// Get Dependabot Alerts
	var DependabotAlertRestsContainer []DependabotAlertRest
	DependabotAlertRests := getDependabotAlertRests(githubToken, githubOrganization, DependabotAlertRestsContainer, 1)

	// Convert JSON to CSV
	dependabotFile, err := os.OpenFile("dependabot.csv", os.O_RDWR|os.O_CREATE, os.ModePerm)
	if err != nil {
		panic(err)
	}
	defer dependabotFile.Close()
	gocsv.MarshalCSV(DependabotAlertRests, gocsv.DefaultCSVWriter(dependabotFile))
}

func getCodeScanningAlertRests(githubToken string, organizationName string, alertsContainer []CodeScanningAlertRest, page int) []CodeScanningAlertRest {
	// Create a new request
	req, err := http.NewRequest("GET", "https://api.github.com/orgs/"+organizationName+"/code-scanning/alerts?per_page=100&page="+strconv.Itoa(page), nil)
	if err != nil {
		panic(err)
	}

	// Set the headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", githubToken))

	// Create a new client
	client := &http.Client{}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	bodyString := string(body)

	var alerts []CodeScanningAlertRest
	err = json.Unmarshal([]byte(bodyString), &alerts)
	if err != nil {
		fmt.Println(err)
	}

	if len(alerts) != 0 {
		alertsContainer = append(alertsContainer, alerts...)
		return getCodeScanningAlertRests(githubToken, "", alertsContainer, page+1)
	} else {
		alertsContainer = append(alertsContainer, alerts...)
		return alertsContainer
	}
}

func getSecretScanningAlertRests(githubToken string, organizationName string, alertsContainer []SecretScanningAlertRest, page int) []SecretScanningAlertRest {
	// Create a new request
	req, err := http.NewRequest("GET", "https://api.github.com/orgs/"+organizationName+"/secret-scanning/alerts?per_page=100&page="+strconv.Itoa(page), nil)
	if err != nil {
		panic(err)
	}

	// Set the headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", githubToken))

	// Create a new client
	client := &http.Client{}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	bodyString := string(body)

	var alerts []SecretScanningAlertRest
	err = json.Unmarshal([]byte(bodyString), &alerts)
	if err != nil {
		fmt.Println(err)
	}

	if len(alerts) != 0 {
		alertsContainer = append(alertsContainer, alerts...)
		return getSecretScanningAlertRests(githubToken, "", alertsContainer, page+1)
	} else {
		alertsContainer = append(alertsContainer, alerts...)
		return alertsContainer
	}
}

func getDependabotAlertRests(githubToken string, organizationName string, alertsContainer []DependabotAlertRest, page int) []DependabotAlertRest {
	// Create a new request
	req, err := http.NewRequest("GET", "https://api.github.com/orgs/"+organizationName+"/dependabot/alerts?per_page=100&page="+strconv.Itoa(page), nil)
	if err != nil {
		panic(err)
	}

	// Set the headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("bearer %s", githubToken))

	// Create a new client
	client := &http.Client{}

	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}

	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	bodyString := string(body)

	var alerts []DependabotAlertRest
	err = json.Unmarshal([]byte(bodyString), &alerts)
	if err != nil {
		fmt.Println(err)
	}

	if len(alerts) != 0 {
		// Remove Description from Security Advisory to avoid CSV error and it's useless to build dashboard anyway
		for i := 0; i < len(alerts); i++ {
			alerts[i].SecurityAdvisory.Description = ""
		}

		alertsContainer = append(alertsContainer, alerts...)
		return getDependabotAlertRests(githubToken, "", alertsContainer, page+1)
	} else {
		alertsContainer = append(alertsContainer, alerts...)
		return alertsContainer
	}
}

type CodeScanningAlertRest struct {
	Number           int         `json:"number"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
	URL              string      `json:"url"`
	HTMLURL          string      `json:"html_url"`
	State            string      `json:"state"`
	FixedAt          interface{} `json:"fixed_at"`
	DismissedBy      interface{} `json:"dismissed_by"`
	DismissedAt      interface{} `json:"dismissed_at"`
	DismissedReason  interface{} `json:"dismissed_reason"`
	DismissedComment interface{} `json:"dismissed_comment"`
	Rule             struct {
		ID                    string        `json:"id"`
		Severity              string        `json:"severity"`
		Description           string        `json:"description"`
		Name                  string        `json:"name"`
		Tags                  []interface{} `json:"tags"`
		SecuritySeverityLevel string        `json:"security_severity_level"`
	} `json:"rule"`
	Tool struct {
		Name    string      `json:"name"`
		GUID    interface{} `json:"guid"`
		Version string      `json:"version"`
	} `json:"tool"`
	MostRecentInstance struct {
		Ref         string `json:"ref"`
		AnalysisKey string `json:"analysis_key"`
		Environment string `json:"environment"`
		Category    string `json:"category"`
		State       string `json:"state"`
		CommitSha   string `json:"commit_sha"`
		Message     struct {
			Text string `json:"text"`
		} `json:"message"`
		Location struct {
			Path        string `json:"path"`
			StartLine   int    `json:"start_line"`
			EndLine     int    `json:"end_line"`
			StartColumn int    `json:"start_column"`
			EndColumn   int    `json:"end_column"`
		} `json:"location"`
		Classifications []interface{} `json:"classifications"`
	} `json:"most_recent_instance"`
	InstancesURL string `json:"instances_url"`
	Repository   struct {
		ID       int    `json:"id"`
		NodeID   string `json:"node_id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Private  bool   `json:"private"`
		Owner    struct {
			Login             string `json:"login"`
			ID                int    `json:"id"`
			NodeID            string `json:"node_id"`
			AvatarURL         string `json:"avatar_url"`
			GravatarID        string `json:"gravatar_id"`
			URL               string `json:"url"`
			HTMLURL           string `json:"html_url"`
			FollowersURL      string `json:"followers_url"`
			FollowingURL      string `json:"following_url"`
			GistsURL          string `json:"gists_url"`
			StarredURL        string `json:"starred_url"`
			SubscriptionsURL  string `json:"subscriptions_url"`
			OrganizationsURL  string `json:"organizations_url"`
			ReposURL          string `json:"repos_url"`
			EventsURL         string `json:"events_url"`
			ReceivedEventsURL string `json:"received_events_url"`
			Type              string `json:"type"`
			SiteAdmin         bool   `json:"site_admin"`
		} `json:"owner"`
		HTMLURL          string `json:"html_url"`
		Description      string `json:"description"`
		Fork             bool   `json:"fork"`
		URL              string `json:"url"`
		ForksURL         string `json:"forks_url"`
		KeysURL          string `json:"keys_url"`
		CollaboratorsURL string `json:"collaborators_url"`
		TeamsURL         string `json:"teams_url"`
		HooksURL         string `json:"hooks_url"`
		IssueEventsURL   string `json:"issue_events_url"`
		EventsURL        string `json:"events_url"`
		AssigneesURL     string `json:"assignees_url"`
		BranchesURL      string `json:"branches_url"`
		TagsURL          string `json:"tags_url"`
		BlobsURL         string `json:"blobs_url"`
		GitTagsURL       string `json:"git_tags_url"`
		GitRefsURL       string `json:"git_refs_url"`
		TreesURL         string `json:"trees_url"`
		StatusesURL      string `json:"statuses_url"`
		LanguagesURL     string `json:"languages_url"`
		StargazersURL    string `json:"stargazers_url"`
		ContributorsURL  string `json:"contributors_url"`
		SubscribersURL   string `json:"subscribers_url"`
		SubscriptionURL  string `json:"subscription_url"`
		CommitsURL       string `json:"commits_url"`
		GitCommitsURL    string `json:"git_commits_url"`
		CommentsURL      string `json:"comments_url"`
		IssueCommentURL  string `json:"issue_comment_url"`
		ContentsURL      string `json:"contents_url"`
		CompareURL       string `json:"compare_url"`
		MergesURL        string `json:"merges_url"`
		ArchiveURL       string `json:"archive_url"`
		DownloadsURL     string `json:"downloads_url"`
		IssuesURL        string `json:"issues_url"`
		PullsURL         string `json:"pulls_url"`
		MilestonesURL    string `json:"milestones_url"`
		NotificationsURL string `json:"notifications_url"`
		LabelsURL        string `json:"labels_url"`
		ReleasesURL      string `json:"releases_url"`
		DeploymentsURL   string `json:"deployments_url"`
	} `json:"repository"`
}

type SecretScanningAlertRest struct {
	Number                   int         `json:"number"`
	CreatedAt                time.Time   `json:"created_at"`
	UpdatedAt                time.Time   `json:"updated_at"`
	URL                      string      `json:"url"`
	HTMLURL                  string      `json:"html_url"`
	LocationsURL             string      `json:"locations_url"`
	State                    string      `json:"state"`
	SecretType               string      `json:"secret_type"`
	SecretTypeDisplayName    string      `json:"secret_type_display_name"`
	Secret                   string      `json:"secret"`
	Validity                 string      `json:"validity"`
	Resolution               interface{} `json:"resolution"`
	ResolvedBy               interface{} `json:"resolved_by"`
	ResolvedAt               interface{} `json:"resolved_at"`
	ResolutionComment        interface{} `json:"resolution_comment"`
	PushProtectionBypassed   bool        `json:"push_protection_bypassed"`
	PushProtectionBypassedBy interface{} `json:"push_protection_bypassed_by"`
	PushProtectionBypassedAt interface{} `json:"push_protection_bypassed_at"`
	Repository               struct {
		ID       int    `json:"id"`
		NodeID   string `json:"node_id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Private  bool   `json:"private"`
		Owner    struct {
			Login             string `json:"login"`
			ID                int    `json:"id"`
			NodeID            string `json:"node_id"`
			AvatarURL         string `json:"avatar_url"`
			GravatarID        string `json:"gravatar_id"`
			URL               string `json:"url"`
			HTMLURL           string `json:"html_url"`
			FollowersURL      string `json:"followers_url"`
			FollowingURL      string `json:"following_url"`
			GistsURL          string `json:"gists_url"`
			StarredURL        string `json:"starred_url"`
			SubscriptionsURL  string `json:"subscriptions_url"`
			OrganizationsURL  string `json:"organizations_url"`
			ReposURL          string `json:"repos_url"`
			EventsURL         string `json:"events_url"`
			ReceivedEventsURL string `json:"received_events_url"`
			Type              string `json:"type"`
			SiteAdmin         bool   `json:"site_admin"`
		} `json:"owner"`
		HTMLURL          string `json:"html_url"`
		Description      string `json:"description"`
		Fork             bool   `json:"fork"`
		URL              string `json:"url"`
		ForksURL         string `json:"forks_url"`
		KeysURL          string `json:"keys_url"`
		CollaboratorsURL string `json:"collaborators_url"`
		TeamsURL         string `json:"teams_url"`
		HooksURL         string `json:"hooks_url"`
		IssueEventsURL   string `json:"issue_events_url"`
		EventsURL        string `json:"events_url"`
		AssigneesURL     string `json:"assignees_url"`
		BranchesURL      string `json:"branches_url"`
		TagsURL          string `json:"tags_url"`
		BlobsURL         string `json:"blobs_url"`
		GitTagsURL       string `json:"git_tags_url"`
		GitRefsURL       string `json:"git_refs_url"`
		TreesURL         string `json:"trees_url"`
		StatusesURL      string `json:"statuses_url"`
		LanguagesURL     string `json:"languages_url"`
		StargazersURL    string `json:"stargazers_url"`
		ContributorsURL  string `json:"contributors_url"`
		SubscribersURL   string `json:"subscribers_url"`
		SubscriptionURL  string `json:"subscription_url"`
		CommitsURL       string `json:"commits_url"`
		GitCommitsURL    string `json:"git_commits_url"`
		CommentsURL      string `json:"comments_url"`
		IssueCommentURL  string `json:"issue_comment_url"`
		ContentsURL      string `json:"contents_url"`
		CompareURL       string `json:"compare_url"`
		MergesURL        string `json:"merges_url"`
		ArchiveURL       string `json:"archive_url"`
		DownloadsURL     string `json:"downloads_url"`
		IssuesURL        string `json:"issues_url"`
		PullsURL         string `json:"pulls_url"`
		MilestonesURL    string `json:"milestones_url"`
		NotificationsURL string `json:"notifications_url"`
		LabelsURL        string `json:"labels_url"`
		ReleasesURL      string `json:"releases_url"`
		DeploymentsURL   string `json:"deployments_url"`
	} `json:"repository"`
}

type DependabotAlertRest struct {
	Number     int    `json:"number"`
	State      string `json:"state"`
	Dependency struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		ManifestPath string `json:"manifest_path"`
		Scope        string `json:"scope"`
	} `json:"dependency"`
	SecurityAdvisory struct {
		GhsaID      string `json:"ghsa_id"`
		CveID       string `json:"cve_id"`
		Summary     string `json:"summary"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Identifiers []struct {
			Value string `json:"value"`
			Type  string `json:"type"`
		} `json:"identifiers"`
		References []struct {
			URL string `json:"url"`
		} `json:"references"`
		PublishedAt     time.Time   `json:"published_at"`
		UpdatedAt       time.Time   `json:"updated_at"`
		WithdrawnAt     interface{} `json:"withdrawn_at"`
		Vulnerabilities []struct {
			Package struct {
				Ecosystem string `json:"ecosystem"`
				Name      string `json:"name"`
			} `json:"package"`
			Severity               string      `json:"severity"`
			VulnerableVersionRange string      `json:"vulnerable_version_range"`
			FirstPatchedVersion    interface{} `json:"first_patched_version"`
		} `json:"vulnerabilities"`
		Cvss struct {
			VectorString string  `json:"vector_string"`
			Score        float64 `json:"score"`
		} `json:"cvss"`
		Cwes []struct {
			CweID string `json:"cwe_id"`
			Name  string `json:"name"`
		} `json:"cwes"`
	} `json:"security_advisory"`
	SecurityVulnerability struct {
		Package struct {
			Ecosystem string `json:"ecosystem"`
			Name      string `json:"name"`
		} `json:"package"`
		Severity               string `json:"severity"`
		VulnerableVersionRange string `json:"vulnerable_version_range"`
		FirstPatchedVersion    struct {
			Identifier string `json:"identifier"`
		} `json:"first_patched_version"`
	} `json:"security_vulnerability"`
	URL              string      `json:"url"`
	HTMLURL          string      `json:"html_url"`
	CreatedAt        time.Time   `json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`
	DismissedAt      interface{} `json:"dismissed_at"`
	DismissedBy      interface{} `json:"dismissed_by"`
	DismissedReason  interface{} `json:"dismissed_reason"`
	DismissedComment interface{} `json:"dismissed_comment"`
	FixedAt          interface{} `json:"fixed_at"`
	AutoDismissedAt  interface{} `json:"auto_dismissed_at"`
	Repository       struct {
		ID       int    `json:"id"`
		NodeID   string `json:"node_id"`
		Name     string `json:"name"`
		FullName string `json:"full_name"`
		Private  bool   `json:"private"`
		Owner    struct {
			Login             string `json:"login"`
			ID                int    `json:"id"`
			NodeID            string `json:"node_id"`
			AvatarURL         string `json:"avatar_url"`
			GravatarID        string `json:"gravatar_id"`
			URL               string `json:"url"`
			HTMLURL           string `json:"html_url"`
			FollowersURL      string `json:"followers_url"`
			FollowingURL      string `json:"following_url"`
			GistsURL          string `json:"gists_url"`
			StarredURL        string `json:"starred_url"`
			SubscriptionsURL  string `json:"subscriptions_url"`
			OrganizationsURL  string `json:"organizations_url"`
			ReposURL          string `json:"repos_url"`
			EventsURL         string `json:"events_url"`
			ReceivedEventsURL string `json:"received_events_url"`
			Type              string `json:"type"`
			SiteAdmin         bool   `json:"site_admin"`
		} `json:"owner"`
		HTMLURL          string `json:"html_url"`
		Description      string `json:"description"`
		Fork             bool   `json:"fork"`
		URL              string `json:"url"`
		ForksURL         string `json:"forks_url"`
		KeysURL          string `json:"keys_url"`
		CollaboratorsURL string `json:"collaborators_url"`
		TeamsURL         string `json:"teams_url"`
		HooksURL         string `json:"hooks_url"`
		IssueEventsURL   string `json:"issue_events_url"`
		EventsURL        string `json:"events_url"`
		AssigneesURL     string `json:"assignees_url"`
		BranchesURL      string `json:"branches_url"`
		TagsURL          string `json:"tags_url"`
		BlobsURL         string `json:"blobs_url"`
		GitTagsURL       string `json:"git_tags_url"`
		GitRefsURL       string `json:"git_refs_url"`
		TreesURL         string `json:"trees_url"`
		StatusesURL      string `json:"statuses_url"`
		LanguagesURL     string `json:"languages_url"`
		StargazersURL    string `json:"stargazers_url"`
		ContributorsURL  string `json:"contributors_url"`
		SubscribersURL   string `json:"subscribers_url"`
		SubscriptionURL  string `json:"subscription_url"`
		CommitsURL       string `json:"commits_url"`
		GitCommitsURL    string `json:"git_commits_url"`
		CommentsURL      string `json:"comments_url"`
		IssueCommentURL  string `json:"issue_comment_url"`
		ContentsURL      string `json:"contents_url"`
		CompareURL       string `json:"compare_url"`
		MergesURL        string `json:"merges_url"`
		ArchiveURL       string `json:"archive_url"`
		DownloadsURL     string `json:"downloads_url"`
		IssuesURL        string `json:"issues_url"`
		PullsURL         string `json:"pulls_url"`
		MilestonesURL    string `json:"milestones_url"`
		NotificationsURL string `json:"notifications_url"`
		LabelsURL        string `json:"labels_url"`
		ReleasesURL      string `json:"releases_url"`
		DeploymentsURL   string `json:"deployments_url"`
	} `json:"repository"`
}
