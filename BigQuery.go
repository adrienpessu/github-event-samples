package main

import (
	"cloud.google.com/go/bigquery"
	"context"
	"fmt"
)

func insertSecretScanningAlertRow(secretScanningAlert []*SecretScanningAlert) error {
	ctx := context.Background()

	// Sets your Google Cloud Platform project ID.
	projectID := "github-webhook-424209"
	dataSet := "webhooks"
	table := "SecretScanningAlert"

	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("bigquery.NewClient: %w", err)
	}
	defer client.Close()

	q := client.Query(fmt.Sprintf("SELECT number, RepositoryFullName FROM `%s.%s.%s` where Number = %d and RepositoryFullName = '%s' ", projectID, dataSet, table, secretScanningAlert[0].Number, secretScanningAlert[0].RepositoryFullName))

	// Execute the query.
	it, err := q.Read(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	secretScanningAlert[0].Version = int(it.TotalRows) + 1

	inserter := client.Dataset(dataSet).Table(table).Inserter()
	if err := inserter.Put(ctx, secretScanningAlert); err != nil {
		return err
	}

	return nil
}

func insertCodeScanningAlertRow(codeScanningAlert []*CodeScanningAlert) error {
	ctx := context.Background()

	// Sets your Google Cloud Platform project ID.
	projectID := "github-webhook-424209"
	dataSet := "webhooks"
	table := "CodeScanningAlert"

	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("bigquery.NewClient: %w", err)
	}
	defer client.Close()

	q := client.Query(fmt.Sprintf("SELECT number, RepositoryFullName FROM `%s.%s.%s` where Number = %d and RepositoryFullName = '%s' ", projectID, dataSet, table, codeScanningAlert[0].Number, codeScanningAlert[0].RepositoryFullName))

	// Execute the query.
	it, err := q.Read(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	codeScanningAlert[0].Version = int(it.TotalRows) + 1

	inserter := client.Dataset(dataSet).Table(table).Inserter()
	if err := inserter.Put(ctx, codeScanningAlert); err != nil {
		return err
	}

	return nil
}

func insertDependabotAlertRow(dependabotAlert []*DependabotAlert) error {
	ctx := context.Background()

	// Sets your Google Cloud Platform project ID.
	projectID := "github-webhook-424209"
	dataSet := "webhooks"
	table := "DependabotAlert"

	client, err := bigquery.NewClient(ctx, projectID)
	if err != nil {
		return fmt.Errorf("bigquery.NewClient: %w", err)
	}
	defer client.Close()

	q := client.Query(fmt.Sprintf("SELECT number, RepositoryFullName FROM `%s.%s.%s` where Number = %d and RepositoryFullName = '%s' ", projectID, dataSet, table, dependabotAlert[0].Number, dependabotAlert[0].RepositoryFullName))

	// Execute the query.
	it, err := q.Read(ctx)
	if err != nil {
		// TODO: Handle error.
	}

	dependabotAlert[0].Version = int(it.TotalRows) + 1

	inserter := client.Dataset(dataSet).Table(table).Inserter()
	if err := inserter.Put(ctx, dependabotAlert); err != nil {
		return err
	}

	return nil
}
