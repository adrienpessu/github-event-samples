package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log"
	"net/http"
	"os"
)

func APIPort() string {
	port := ":8080"
	if val, ok := os.LookupEnv("FUNCTIONS_CUSTOMHANDLER_PORT"); ok {
		port = ":" + val
	}
	return port
}

func secretAlertHandle(c *gin.Context) {
	log.Println("secret Scanning handler is in progress...")
	body, err := io.ReadAll(c.Request.Body)

	if !VerifySignature(c.Request, body) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": "Unauthorized",
		})
		return
	}

	if err != nil {
		log.Println("Error reading request body:", err.Error())
		return
	}
	bodyString := string(body)

	// Marshal the body into a struct
	var payload PayloadSecret
	err = json.Unmarshal([]byte(bodyString), &payload)

	// create SecretScanningAlert from payload
	alerts := []*SecretScanningAlert{
		// Item implements the ValueSaver interface.
		{
			Number:                   payload.Alert.Number,
			CreatedAt:                payload.Alert.CreatedAt,
			UpdatedAt:                payload.Alert.UpdatedAt,
			URL:                      payload.Alert.URL,
			HTMLURL:                  payload.Alert.HTMLURL,
			LocationsURL:             payload.Alert.LocationsURL,
			State:                    "open",
			SecretType:               payload.Alert.SecretType,
			SecretTypeDisplayName:    payload.Alert.SecretType,
			Validity:                 payload.Alert.Validity,
			Resolution:               fmt.Sprintf("%#v", payload.Alert.Resolution),
			ResolvedBy:               fmt.Sprintf("%#v", payload.Alert.ResolvedBy),
			ResolvedAt:               fmt.Sprintf("%#v", payload.Alert.ResolvedAt),
			ResolutionComment:        fmt.Sprintf("%#v", payload.Alert.ResolutionComment),
			PushProtectionBypassed:   fmt.Sprintf("%#v", payload.Alert.PushProtectionBypassed),
			PushProtectionBypassedBy: fmt.Sprintf("%#v", payload.Alert.PushProtectionBypassedBy),
			PushProtectionBypassedAt: fmt.Sprintf("%#v", payload.Alert.PushProtectionBypassedAt),
			RepositoryFullName:       payload.Repository.FullName,
		},
	}

	errSecretScanningAlert := insertSecretScanningAlertRow(alerts)
	if errSecretScanningAlert != nil {
		log.Println("Error inserting row into BigQuery:", errSecretScanningAlert.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
	log.Println("secret Scanning handler is done")
	// return
}

func codeAlertHandle(c *gin.Context) {
	log.Println("secret Scanning handler is in progress...")

	body, err := io.ReadAll(c.Request.Body)

	if !VerifySignature(c.Request, body) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": "Unauthorized",
		})
		return
	}

	if err != nil {
		log.Println("Error reading request body:", err.Error())
		return
	}
	bodyString := string(body)

	// Marshal the body into a struct
	var payload PayloadCode
	err = json.Unmarshal([]byte(bodyString), &payload)

	// create SecretScanningAlert from payload
	alerts := []*CodeScanningAlert{
		// Item implements the ValueSaver interface.
		{
			Number:                    payload.Alert.Number,
			CreatedAt:                 payload.Alert.CreatedAt,
			UpdatedAt:                 payload.Alert.UpdatedAt,
			URL:                       payload.Alert.URL,
			HTMLURL:                   payload.Alert.HTMLURL,
			State:                     payload.Alert.State,
			FixedAt:                   fmt.Sprintf("%#v", payload.Alert.FixedAt),
			DismissedBy:               fmt.Sprintf("%#v", payload.Alert.DismissedBy),
			DismissedAt:               fmt.Sprintf("%#v", payload.Alert.DismissedAt),
			DismissedReason:           fmt.Sprintf("%#v", payload.Alert.DismissedReason),
			DismissedComment:          fmt.Sprintf("%#v", payload.Alert.DismissedComment),
			RepositoryFullName:        payload.Repository.FullName,
			RuleId:                    payload.Alert.Rule.ID,
			RuleSeverity:              payload.Alert.Rule.Severity,
			RuleDescription:           payload.Alert.Rule.Description,
			RuleName:                  payload.Alert.Rule.Name,
			RuleSecuritySeverityLevel: payload.Alert.Rule.SecuritySeverityLevel,
			InstancesURL:              payload.Alert.InstancesURL,
		},
	}

	errSecretScanningAlert := insertCodeScanningAlertRow(alerts)
	if errSecretScanningAlert != nil {
		log.Println("Error inserting row into BigQuery:", errSecretScanningAlert.Error())
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
	log.Println("secret Scanning handler is done")
}

func dependabotAlertHandle(c *gin.Context) {
	log.Println("secret Scanning handler is in progress...")

	body, err := io.ReadAll(c.Request.Body)
	if !VerifySignature(c.Request, body) {
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": "Unauthorized",
		})
		return
	}

	if err != nil {
		log.Println("Error reading request body:", err.Error())
		return
	}
	bodyString := string(body)

	// Marshal the body into a struct
	var payload PayloadDependabot
	err = json.Unmarshal([]byte(bodyString), &payload)

	// create SecretScanningAlert from payload
	alerts := []*DependabotAlert{
		// Item implements the ValueSaver interface.
		{
			Number:                                  payload.Alert.Number,
			State:                                   payload.Alert.State,
			DependencyPackageEcosystem:              payload.Alert.Dependency.Package.Ecosystem,
			DependencyPackageName:                   payload.Alert.Dependency.Package.Name,
			DependencyManifestPath:                  payload.Alert.Dependency.ManifestPath,
			DependencyScope:                         payload.Alert.Dependency.Scope,
			SecurityAdvisoryGhsaID:                  payload.Alert.SecurityAdvisory.GhsaID,
			SecurityAdvisoryCveID:                   payload.Alert.SecurityAdvisory.CveID,
			SecurityAdvisorySummary:                 payload.Alert.SecurityAdvisory.Summary,
			SecurityAdvisoryDescription:             payload.Alert.SecurityAdvisory.Description,
			SecurityAdvisorySeverity:                payload.Alert.SecurityAdvisory.Severity,
			SecurityAdvisoryReferencesURL:           payload.Alert.SecurityAdvisory.References[0].URL,
			SecurityAdvisoryPublishedAt:             payload.Alert.SecurityAdvisory.PublishedAt,
			SecurityAdvisoryUpdatedAt:               payload.Alert.SecurityAdvisory.UpdatedAt,
			SecurityAdvisoryWithdrawnAt:             fmt.Sprintf("%#v", payload.Alert.SecurityAdvisory.WithdrawnAt),
			SecurityAdvisoryVulnerabilitiesSeverity: payload.Alert.SecurityAdvisory.Vulnerabilities[0].Severity,
			SecurityAdvisoryVulnerabilitiesVulnerableVersionRange: payload.Alert.SecurityAdvisory.Vulnerabilities[0].VulnerableVersionRange,
			SecurityAdvisoryCvssVectorString:                      payload.Alert.SecurityAdvisory.Cvss.VectorString,
			SecurityAdvisoryCvssScore:                             payload.Alert.SecurityAdvisory.Cvss.Score,
			SecurityAdvisoryCwesCweID:                             payload.Alert.SecurityAdvisory.Cwes[0].CweID,
			SecurityAdvisoryCwesName:                              payload.Alert.SecurityAdvisory.Cwes[0].Name,
			URL:                                                   payload.Alert.URL,
			HTMLURL:                                               payload.Alert.HTMLURL,
			CreatedAt:                                             payload.Alert.CreatedAt,
			UpdatedAt:                                             payload.Alert.UpdatedAt,
			DismissedAt:                                           fmt.Sprintf("%#v", payload.Alert.DismissedAt),
			DismissedBy:                                           fmt.Sprintf("%#v", payload.Alert.DismissedBy),
			DismissedReason:                                       fmt.Sprintf("%#v", payload.Alert.DismissedReason),
			DismissedComment:                                      fmt.Sprintf("%#v", payload.Alert.DismissedComment),
			FixedAt:                                               fmt.Sprintf("%#v", payload.Alert.FixedAt),
			AutoDismissedAt:                                       fmt.Sprintf("%#v", payload.Alert.AutoDismissedAt),
			RepositoryFullName:                                    payload.Repository.FullName,
		},
	}

	errSecretScanningAlert := insertDependabotAlertRow(alerts)
	if errSecretScanningAlert != nil {
		log.Println("Error inserting row into BigQuery:", errSecretScanningAlert.Error())
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"status": "ok",
	})
	log.Println("secret Scanning handler is done")
}

func VerifySignature(req *http.Request, body []byte) bool {
	var WebhookSecret = os.Getenv("WEBHOOK_SECRET")

	mac := hmac.New(sha256.New, []byte(WebhookSecret))
	mac.Write(body)
	expectedMAC := mac.Sum(nil)
	signature := req.Header.Get("X-Hub-Signature-256")

	// Remove the 'sha256=' prefix
	signature = signature[7:]
	receivedMAC, _ := hex.DecodeString(signature)

	return hmac.Equal(receivedMAC, expectedMAC)
}

func main() {
	router := gin.Default()
	router.POST("api/secret", secretAlertHandle)
	router.POST("api/code", codeAlertHandle)
	router.POST("api/dependabot", dependabotAlertHandle)

	port_info := APIPort()
	router.Run(port_info)
	log.Println("API is up & running - " + port_info)
}
