# github-event-samples

This repository contains a collection of sample payloads for various GitHub webhook events. The payloads are stored in the `samples` directory and are organized by event type.

The file `api.go` contains three endpoints, one for each WebHook event : `code_scanning_alert`, `secret_scanning_alert` and `dependabot_alert`. Each endpoint will receive the payload from the corresponding event, flatten the payload and insert it into a BigQuery table.

The file `bigquery.go` contains the code to insert the payload into a BigQuery table.

The file `payload.go` contains the struct of the WebHook event payload.

The file `Model.go` contains the struct of the BigQuery table.

The file `export.go` contains the code to export the GHAS alert using the REST API and store it to a CSV file.