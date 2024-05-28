package main

import (
	"time"
)

type SecretScanningAlert struct {
	Number                int       `json:"number"`
	Version               int       `json:"version"`
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
	URL                   string    `json:"url"`
	HTMLURL               string    `json:"html_url"`
	LocationsURL          string    `json:"locations_url"`
	State                 string    `json:"state"`
	SecretType            string    `json:"secret_type"`
	SecretTypeDisplayName string    `json:"secret_type_display_name"`
	//Secret                   string    `json:"secret"`
	Validity                 string `json:"validity"`
	Resolution               string `json:"resolution"`
	ResolvedBy               string `json:"resolved_by"`
	ResolvedAt               string `json:"resolved_at"`
	ResolutionComment        string `json:"resolution_comment"`
	PushProtectionBypassed   string `json:"push_protection_bypassed"`
	PushProtectionBypassedBy string `json:"push_protection_bypassed_by"`
	PushProtectionBypassedAt string `json:"push_protection_bypassed_at"`
	RepositoryFullName       string `json:"repository_full_name"`
	//Repository               struct {
	//	ID       int    `json:"id"`
	//	NodeID   string `json:"node_id"`
	//	Name     string `json:"name"`
	//	FullName string `json:"full_name"`
	//	Private  bool   `json:"private"`
	//	Owner    struct {
	//		Login             string `json:"login"`
	//		ID                int    `json:"id"`
	//		NodeID            string `json:"node_id"`
	//		AvatarURL         string `json:"avatar_url"`
	//		GravatarID        string `json:"gravatar_id"`
	//		URL               string `json:"url"`
	//		HTMLURL           string `json:"html_url"`
	//		FollowersURL      string `json:"followers_url"`
	//		FollowingURL      string `json:"following_url"`
	//		GistsURL          string `json:"gists_url"`
	//		StarredURL        string `json:"starred_url"`
	//		SubscriptionsURL  string `json:"subscriptions_url"`
	//		OrganizationsURL  string `json:"organizations_url"`
	//		ReposURL          string `json:"repos_url"`
	//		EventsURL         string `json:"events_url"`
	//		ReceivedEventsURL string `json:"received_events_url"`
	//		Type              string `json:"type"`
	//		SiteAdmin         bool   `json:"site_admin"`
	//	} `json:"owner"`
	//	HTMLURL          string `json:"html_url"`
	//	Description      string `json:"description"`
	//	Fork             bool   `json:"fork"`
	//	URL              string `json:"url"`
	//	ForksURL         string `json:"forks_url"`
	//	KeysURL          string `json:"keys_url"`
	//	CollaboratorsURL string `json:"collaborators_url"`
	//	TeamsURL         string `json:"teams_url"`
	//	HooksURL         string `json:"hooks_url"`
	//	IssueEventsURL   string `json:"issue_events_url"`
	//	EventsURL        string `json:"events_url"`
	//	AssigneesURL     string `json:"assignees_url"`
	//	BranchesURL      string `json:"branches_url"`
	//	TagsURL          string `json:"tags_url"`
	//	BlobsURL         string `json:"blobs_url"`
	//	GitTagsURL       string `json:"git_tags_url"`
	//	GitRefsURL       string `json:"git_refs_url"`
	//	TreesURL         string `json:"trees_url"`
	//	StatusesURL      string `json:"statuses_url"`
	//	LanguagesURL     string `json:"languages_url"`
	//	StargazersURL    string `json:"stargazers_url"`
	//	ContributorsURL  string `json:"contributors_url"`
	//	SubscribersURL   string `json:"subscribers_url"`
	//	SubscriptionURL  string `json:"subscription_url"`
	//	CommitsURL       string `json:"commits_url"`
	//	GitCommitsURL    string `json:"git_commits_url"`
	//	CommentsURL      string `json:"comments_url"`
	//	IssueCommentURL  string `json:"issue_comment_url"`
	//	ContentsURL      string `json:"contents_url"`
	//	CompareURL       string `json:"compare_url"`
	//	MergesURL        string `json:"merges_url"`
	//	ArchiveURL       string `json:"archive_url"`
	//	DownloadsURL     string `json:"downloads_url"`
	//	IssuesURL        string `json:"issues_url"`
	//	PullsURL         string `json:"pulls_url"`
	//	MilestonesURL    string `json:"milestones_url"`
	//	NotificationsURL string `json:"notifications_url"`
	//	LabelsURL        string `json:"labels_url"`
	//	ReleasesURL      string `json:"releases_url"`
	//	DeploymentsURL   string `json:"deployments_url"`
	//} `json:"repository"`
}

type CodeScanningAlert struct {
	Number                    int       `json:"number"`
	Version                   int       `json:"version"`
	CreatedAt                 time.Time `json:"created_at"`
	UpdatedAt                 time.Time `json:"updated_at"`
	URL                       string    `json:"url"`
	HTMLURL                   string    `json:"html_url"`
	State                     string    `json:"state"`
	FixedAt                   string    `json:"fixed_at"`
	DismissedBy               string    `json:"dismissed_by"`
	DismissedAt               string    `json:"dismissed_at"`
	DismissedReason           string    `json:"dismissed_reason"`
	DismissedComment          string    `json:"dismissed_comment"`
	RepositoryFullName        string    `json:"repository_full_name"`
	RuleId                    string    `json:"rule_id"`
	RuleSeverity              string    `json:"rule_severity"`
	RuleDescription           string    `json:"rule_description"`
	RuleName                  string    `json:"rule_name"`
	RuleSecuritySeverityLevel string    `json:"rule_security_severity_level"`
	InstancesURL              string    `json:"instances_url"`

	//RuleTags []interface{}      `json:"rule_tags"`
	//Rule             struct {
	//	ID                    string        `json:"id"`
	//	Severity              string        `json:"severity"`
	//	Description           string        `json:"description"`
	//	Name                  string        `json:"name"`
	//	Tags                  []interface{} `json:"tags"`
	//	SecuritySeverityLevel string        `json:"security_severity_level"`
	//} `json:"rule"`
	//Tool struct {
	//	Name    string      `json:"name"`
	//	GUID    interface{} `json:"guid"`
	//	Version string      `json:"version"`
	//} `json:"tool"`
	//MostRecentInstance struct {
	//	Ref         string `json:"ref"`
	//	AnalysisKey string `json:"analysis_key"`
	//	Environment string `json:"environment"`
	//	Category    string `json:"category"`
	//	State       string `json:"state"`
	//	CommitSha   string `json:"commit_sha"`
	//	Message     struct {
	//		Text string `json:"text"`
	//	} `json:"message"`
	//	Location struct {
	//		Path        string `json:"path"`
	//		StartLine   int    `json:"start_line"`
	//		EndLine     int    `json:"end_line"`
	//		StartColumn int    `json:"start_column"`
	//		EndColumn   int    `json:"end_column"`
	//	} `json:"location"`
	//	Classifications []interface{} `json:"classifications"`
	//} `json:"most_recent_instance"`
	//Repository   struct {
	//	ID       int    `json:"id"`
	//	NodeID   string `json:"node_id"`
	//	Name     string `json:"name"`
	//	FullName string `json:"full_name"`
	//	Private  bool   `json:"private"`
	//	Owner    struct {
	//		Login             string `json:"login"`
	//		ID                int    `json:"id"`
	//		NodeID            string `json:"node_id"`
	//		AvatarURL         string `json:"avatar_url"`
	//		GravatarID        string `json:"gravatar_id"`
	//		URL               string `json:"url"`
	//		HTMLURL           string `json:"html_url"`
	//		FollowersURL      string `json:"followers_url"`
	//		FollowingURL      string `json:"following_url"`
	//		GistsURL          string `json:"gists_url"`
	//		StarredURL        string `json:"starred_url"`
	//		SubscriptionsURL  string `json:"subscriptions_url"`
	//		OrganizationsURL  string `json:"organizations_url"`
	//		ReposURL          string `json:"repos_url"`
	//		EventsURL         string `json:"events_url"`
	//		ReceivedEventsURL string `json:"received_events_url"`
	//		Type              string `json:"type"`
	//		SiteAdmin         bool   `json:"site_admin"`
	//	} `json:"owner"`
	//	HTMLURL          string `json:"html_url"`
	//	Description      string `json:"description"`
	//	Fork             bool   `json:"fork"`
	//	URL              string `json:"url"`
	//	ForksURL         string `json:"forks_url"`
	//	KeysURL          string `json:"keys_url"`
	//	CollaboratorsURL string `json:"collaborators_url"`
	//	TeamsURL         string `json:"teams_url"`
	//	HooksURL         string `json:"hooks_url"`
	//	IssueEventsURL   string `json:"issue_events_url"`
	//	EventsURL        string `json:"events_url"`
	//	AssigneesURL     string `json:"assignees_url"`
	//	BranchesURL      string `json:"branches_url"`
	//	TagsURL          string `json:"tags_url"`
	//	BlobsURL         string `json:"blobs_url"`
	//	GitTagsURL       string `json:"git_tags_url"`
	//	GitRefsURL       string `json:"git_refs_url"`
	//	TreesURL         string `json:"trees_url"`
	//	StatusesURL      string `json:"statuses_url"`
	//	LanguagesURL     string `json:"languages_url"`
	//	StargazersURL    string `json:"stargazers_url"`
	//	ContributorsURL  string `json:"contributors_url"`
	//	SubscribersURL   string `json:"subscribers_url"`
	//	SubscriptionURL  string `json:"subscription_url"`
	//	CommitsURL       string `json:"commits_url"`
	//	GitCommitsURL    string `json:"git_commits_url"`
	//	CommentsURL      string `json:"comments_url"`
	//	IssueCommentURL  string `json:"issue_comment_url"`
	//	ContentsURL      string `json:"contents_url"`
	//	CompareURL       string `json:"compare_url"`
	//	MergesURL        string `json:"merges_url"`
	//	ArchiveURL       string `json:"archive_url"`
	//	DownloadsURL     string `json:"downloads_url"`
	//	IssuesURL        string `json:"issues_url"`
	//	PullsURL         string `json:"pulls_url"`
	//	MilestonesURL    string `json:"milestones_url"`
	//	NotificationsURL string `json:"notifications_url"`
	//	LabelsURL        string `json:"labels_url"`
	//	ReleasesURL      string `json:"releases_url"`
	//	DeploymentsURL   string `json:"deployments_url"`
	//} `json:"repository"`
}

type DependabotAlert struct {
	Number                                                int       `json:"number"`
	State                                                 string    `json:"state"`
	Version                                               int       `json:"version"`
	DependencyPackageEcosystem                            string    `json:"dependency_package_ecosystem"`
	DependencyPackageName                                 string    `json:"dependency_package_name"`
	DependencyManifestPath                                string    `json:"dependency_manifest_path"`
	DependencyScope                                       string    `json:"dependency_scope"`
	SecurityAdvisoryGhsaID                                string    `json:"security_advisory_ghsa_id"`
	SecurityAdvisoryCveID                                 string    `json:"security_advisory_cve_id"`
	SecurityAdvisorySummary                               string    `json:"security_advisory_summary"`
	SecurityAdvisoryDescription                           string    `json:"security_advisory_description"`
	SecurityAdvisorySeverity                              string    `json:"security_advisory_severity"`
	SecurityAdvisoryReferencesURL                         string    `json:"security_advisory_references_url"`
	SecurityAdvisoryPublishedAt                           time.Time `json:"security_advisory_published_at"`
	SecurityAdvisoryUpdatedAt                             time.Time `json:"security_advisory_updated_at"`
	SecurityAdvisoryWithdrawnAt                           string    `json:"security_advisory_withdrawn_at"`
	SecurityAdvisoryVulnerabilitiesSeverity               string    `json:"security_advisory_vulnerabilities_severity"`
	SecurityAdvisoryVulnerabilitiesVulnerableVersionRange string    `json:"security_advisory_vulnerabilities_vulnerable_version_range"`
	SecurityAdvisoryCvssVectorString                      string    `json:"security_advisory_cvss_vector_string"`
	SecurityAdvisoryCvssScore                             float64   `json:"security_advisory_cvss_score"`
	SecurityAdvisoryCwesCweID                             string    `json:"security_advisory_cwes_cwe_id"`
	SecurityAdvisoryCwesName                              string    `json:"security_advisory_cwes_name"`
	URL                                                   string    `json:"url"`
	HTMLURL                                               string    `json:"html_url"`
	CreatedAt                                             time.Time `json:"created_at"`
	UpdatedAt                                             time.Time `json:"updated_at"`
	DismissedAt                                           string    `json:"dismissed_at"`
	DismissedBy                                           string    `json:"dismissed_by"`
	DismissedReason                                       string    `json:"dismissed_reason"`
	DismissedComment                                      string    `json:"dismissed_comment"`
	FixedAt                                               string    `json:"fixed_at"`
	AutoDismissedAt                                       string    `json:"auto_dismissed_at"`
	RepositoryFullName                                    string    `json:"repository_full_name"`

	//Dependency struct {
	//	Package struct {
	//		Ecosystem string `json:"ecosystem"`
	//		Name      string `json:"name"`
	//	} `json:"package"`
	//	ManifestPath string `json:"manifest_path"`
	//	Scope        string `json:"scope"`
	//} `json:"dependency"`
	//SecurityAdvisory struct {
	//	GhsaID      string `json:"ghsa_id"`
	//	CveID       string `json:"cve_id"`
	//	Summary     string `json:"summary"`
	//	Description string `json:"description"`
	//	Severity    string `json:"severity"`
	//	Identifiers []struct {
	//		Value string `json:"value"`
	//		Type  string `json:"type"`
	//	} `json:"identifiers"`
	//	References []struct {
	//		URL string `json:"url"`
	//	} `json:"references"`
	//	PublishedAt     time.Time   `json:"published_at"`
	//	UpdatedAt       time.Time   `json:"updated_at"`
	//	WithdrawnAt     interface{} `json:"withdrawn_at"`
	//	Vulnerabilities []struct {
	//		Package struct {
	//			Ecosystem string `json:"ecosystem"`
	//			Name      string `json:"name"`
	//		} `json:"package"`
	//		Severity               string      `json:"severity"`
	//		VulnerableVersionRange string      `json:"vulnerable_version_range"`
	//		FirstPatchedVersion    interface{} `json:"first_patched_version"`
	//	} `json:"vulnerabilities"`
	//	Cvss struct {
	//		VectorString string  `json:"vector_string"`
	//		Score        float64 `json:"score"`
	//	} `json:"cvss"`
	//	Cwes []struct {
	//		CweID string `json:"cwe_id"`
	//		Name  string `json:"name"`
	//	} `json:"cwes"`
	//} `json:"security_advisory"`
	//SecurityVulnerability struct {
	//	Package struct {
	//		Ecosystem string `json:"ecosystem"`
	//		Name      string `json:"name"`
	//	} `json:"package"`
	//	Severity               string `json:"severity"`
	//	VulnerableVersionRange string `json:"vulnerable_version_range"`
	//	FirstPatchedVersion    struct {
	//		Identifier string `json:"identifier"`
	//	} `json:"first_patched_version"`
	//} `json:"security_vulnerability"`
	//Repository       struct {
	//	ID       int    `json:"id"`
	//	NodeID   string `json:"node_id"`
	//	Name     string `json:"name"`
	//	FullName string `json:"full_name"`
	//	Private  bool   `json:"private"`
	//	Owner    struct {
	//		Login             string `json:"login"`
	//		ID                int    `json:"id"`
	//		NodeID            string `json:"node_id"`
	//		AvatarURL         string `json:"avatar_url"`
	//		GravatarID        string `json:"gravatar_id"`
	//		URL               string `json:"url"`
	//		HTMLURL           string `json:"html_url"`
	//		FollowersURL      string `json:"followers_url"`
	//		FollowingURL      string `json:"following_url"`
	//		GistsURL          string `json:"gists_url"`
	//		StarredURL        string `json:"starred_url"`
	//		SubscriptionsURL  string `json:"subscriptions_url"`
	//		OrganizationsURL  string `json:"organizations_url"`
	//		ReposURL          string `json:"repos_url"`
	//		EventsURL         string `json:"events_url"`
	//		ReceivedEventsURL string `json:"received_events_url"`
	//		Type              string `json:"type"`
	//		SiteAdmin         bool   `json:"site_admin"`
	//	} `json:"owner"`
	//	HTMLURL          string `json:"html_url"`
	//	Description      string `json:"description"`
	//	Fork             bool   `json:"fork"`
	//	URL              string `json:"url"`
	//	ForksURL         string `json:"forks_url"`
	//	KeysURL          string `json:"keys_url"`
	//	CollaboratorsURL string `json:"collaborators_url"`
	//	TeamsURL         string `json:"teams_url"`
	//	HooksURL         string `json:"hooks_url"`
	//	IssueEventsURL   string `json:"issue_events_url"`
	//	EventsURL        string `json:"events_url"`
	//	AssigneesURL     string `json:"assignees_url"`
	//	BranchesURL      string `json:"branches_url"`
	//	TagsURL          string `json:"tags_url"`
	//	BlobsURL         string `json:"blobs_url"`
	//	GitTagsURL       string `json:"git_tags_url"`
	//	GitRefsURL       string `json:"git_refs_url"`
	//	TreesURL         string `json:"trees_url"`
	//	StatusesURL      string `json:"statuses_url"`
	//	LanguagesURL     string `json:"languages_url"`
	//	StargazersURL    string `json:"stargazers_url"`
	//	ContributorsURL  string `json:"contributors_url"`
	//	SubscribersURL   string `json:"subscribers_url"`
	//	SubscriptionURL  string `json:"subscription_url"`
	//	CommitsURL       string `json:"commits_url"`
	//	GitCommitsURL    string `json:"git_commits_url"`
	//	CommentsURL      string `json:"comments_url"`
	//	IssueCommentURL  string `json:"issue_comment_url"`
	//	ContentsURL      string `json:"contents_url"`
	//	CompareURL       string `json:"compare_url"`
	//	MergesURL        string `json:"merges_url"`
	//	ArchiveURL       string `json:"archive_url"`
	//	DownloadsURL     string `json:"downloads_url"`
	//	IssuesURL        string `json:"issues_url"`
	//	PullsURL         string `json:"pulls_url"`
	//	MilestonesURL    string `json:"milestones_url"`
	//	NotificationsURL string `json:"notifications_url"`
	//	LabelsURL        string `json:"labels_url"`
	//	ReleasesURL      string `json:"releases_url"`
	//	DeploymentsURL   string `json:"deployments_url"`
	//} `json:"repository"`
}

type AutoGenerated struct {
	Action string `json:"action"`
	Alert  struct {
		Number      int         `json:"number"`
		CreatedAt   time.Time   `json:"created_at"`
		UpdatedAt   time.Time   `json:"updated_at"`
		URL         string      `json:"url"`
		HTMLURL     string      `json:"html_url"`
		State       string      `json:"state"`
		FixedAt     interface{} `json:"fixed_at"`
		DismissedBy struct {
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
		} `json:"dismissed_by"`
		DismissedAt      time.Time   `json:"dismissed_at"`
		DismissedReason  string      `json:"dismissed_reason"`
		DismissedComment interface{} `json:"dismissed_comment"`
		Rule             struct {
			ID                    string   `json:"id"`
			Severity              string   `json:"severity"`
			Description           string   `json:"description"`
			Name                  string   `json:"name"`
			Tags                  []string `json:"tags"`
			FullDescription       string   `json:"full_description"`
			Help                  string   `json:"help"`
			SecuritySeverityLevel string   `json:"security_severity_level"`
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
	} `json:"alert"`
	Ref        string `json:"ref"`
	CommitOid  string `json:"commit_oid"`
	Repository struct {
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
		HTMLURL          string      `json:"html_url"`
		Description      interface{} `json:"description"`
		Fork             bool        `json:"fork"`
		URL              string      `json:"url"`
		ForksURL         string      `json:"forks_url"`
		KeysURL          string      `json:"keys_url"`
		CollaboratorsURL string      `json:"collaborators_url"`
		TeamsURL         string      `json:"teams_url"`
		HooksURL         string      `json:"hooks_url"`
		IssueEventsURL   string      `json:"issue_events_url"`
		EventsURL        string      `json:"events_url"`
		AssigneesURL     string      `json:"assignees_url"`
		BranchesURL      string      `json:"branches_url"`
		TagsURL          string      `json:"tags_url"`
		BlobsURL         string      `json:"blobs_url"`
		GitTagsURL       string      `json:"git_tags_url"`
		GitRefsURL       string      `json:"git_refs_url"`
		TreesURL         string      `json:"trees_url"`
		StatusesURL      string      `json:"statuses_url"`
		LanguagesURL     string      `json:"languages_url"`
		StargazersURL    string      `json:"stargazers_url"`
		ContributorsURL  string      `json:"contributors_url"`
		SubscribersURL   string      `json:"subscribers_url"`
		SubscriptionURL  string      `json:"subscription_url"`
		CommitsURL       string      `json:"commits_url"`
		GitCommitsURL    string      `json:"git_commits_url"`
		CommentsURL      string      `json:"comments_url"`
		IssueCommentURL  string      `json:"issue_comment_url"`
		ContentsURL      string      `json:"contents_url"`
		CompareURL       string      `json:"compare_url"`
		MergesURL        string      `json:"merges_url"`
		ArchiveURL       string      `json:"archive_url"`
		DownloadsURL     string      `json:"downloads_url"`
		IssuesURL        string      `json:"issues_url"`
		PullsURL         string      `json:"pulls_url"`
		MilestonesURL    string      `json:"milestones_url"`
		NotificationsURL string      `json:"notifications_url"`
		LabelsURL        string      `json:"labels_url"`
		ReleasesURL      string      `json:"releases_url"`
		DeploymentsURL   string      `json:"deployments_url"`
		CreatedAt        time.Time   `json:"created_at"`
		UpdatedAt        time.Time   `json:"updated_at"`
		PushedAt         time.Time   `json:"pushed_at"`
		GitURL           string      `json:"git_url"`
		SSHURL           string      `json:"ssh_url"`
		CloneURL         string      `json:"clone_url"`
		SvnURL           string      `json:"svn_url"`
		Homepage         interface{} `json:"homepage"`
		Size             int         `json:"size"`
		StargazersCount  int         `json:"stargazers_count"`
		WatchersCount    int         `json:"watchers_count"`
		Language         string      `json:"language"`
		HasIssues        bool        `json:"has_issues"`
		HasProjects      bool        `json:"has_projects"`
		HasDownloads     bool        `json:"has_downloads"`
		HasWiki          bool        `json:"has_wiki"`
		HasPages         bool        `json:"has_pages"`
		HasDiscussions   bool        `json:"has_discussions"`
		ForksCount       int         `json:"forks_count"`
		MirrorURL        interface{} `json:"mirror_url"`
		Archived         bool        `json:"archived"`
		Disabled         bool        `json:"disabled"`
		OpenIssuesCount  int         `json:"open_issues_count"`
		License          struct {
			Key    string      `json:"key"`
			Name   string      `json:"name"`
			SpdxID string      `json:"spdx_id"`
			URL    interface{} `json:"url"`
			NodeID string      `json:"node_id"`
		} `json:"license"`
		AllowForking             bool          `json:"allow_forking"`
		IsTemplate               bool          `json:"is_template"`
		WebCommitSignoffRequired bool          `json:"web_commit_signoff_required"`
		Topics                   []interface{} `json:"topics"`
		Visibility               string        `json:"visibility"`
		Forks                    int           `json:"forks"`
		OpenIssues               int           `json:"open_issues"`
		Watchers                 int           `json:"watchers"`
		DefaultBranch            string        `json:"default_branch"`
		CustomProperties         struct {
		} `json:"custom_properties"`
	} `json:"repository"`
	Organization struct {
		Login            string `json:"login"`
		ID               int    `json:"id"`
		NodeID           string `json:"node_id"`
		URL              string `json:"url"`
		ReposURL         string `json:"repos_url"`
		EventsURL        string `json:"events_url"`
		HooksURL         string `json:"hooks_url"`
		IssuesURL        string `json:"issues_url"`
		MembersURL       string `json:"members_url"`
		PublicMembersURL string `json:"public_members_url"`
		AvatarURL        string `json:"avatar_url"`
		Description      string `json:"description"`
	} `json:"organization"`
	Enterprise struct {
		ID          int       `json:"id"`
		Slug        string    `json:"slug"`
		Name        string    `json:"name"`
		NodeID      string    `json:"node_id"`
		AvatarURL   string    `json:"avatar_url"`
		Description string    `json:"description"`
		WebsiteURL  string    `json:"website_url"`
		HTMLURL     string    `json:"html_url"`
		CreatedAt   time.Time `json:"created_at"`
		UpdatedAt   time.Time `json:"updated_at"`
	} `json:"enterprise"`
	Sender struct {
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
	} `json:"sender"`
}
