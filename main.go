package main

import (
	"cloud.google.com/go/container"
	"fmt"
	log "github.com/sirupsen/logrus"
	"github.com/speak2jc/google-apis-examples-go/internal"
	"os"
	"time"
)

func main() {

	projectID := "explorer-273804"
	zone := "us-central1-c"

	serviceAccountKeyfilePath := fmt.Sprintf("/Users/jamez/code/go/src/github.com/speak2jc/google-apis-examples-go/keyfiles/%s.json", projectID)
	os.Setenv("GOOGLE_APPLICATION_CREDENTIALS", serviceAccountKeyfilePath)
	containerDetails(projectID, zone)

}

func containerDetails(projectID string, zone string) {
	//================
	// Get auth token
	//================

	token, err := internal.GetAuthToken(projectID)
	if err != nil {
		log.Error(err)
	}
	log.Info(token)

	//================
	// Find clusters
	//================

	clusterID := "cluster-abc"
	clusters, err := internal.FindClustersForProject(projectID, "-")
	if err != nil {
		log.Error(err)
		return
	}
	log.Infof("Clusters: %s", clusters)
	var cluster *container.Resource
	for _, clstr := range clusters {
		if clstr.Name == clusterID {
			cluster = clstr
		}
	}
	log.Infof("Cluster: %s", cluster.Endpoint)

	//==============================================
	// Get endpoint IP address for a given cluster
	// within a project in any zone
	//==============================================

	ip, err := internal.GetIpForCluster(projectID, clusterID)
	if err != nil {
		log.Error(err)
		return
	}
	log.Infof("IP address for cluster %s is %s", clusterID, *ip)

}

func container_analysis(projectID string) {

	//================
	// Common
	//================

	resourceURL := "https://gcr.io/explorer-273804/vulnerabilities-tutorial-image"
	timeout := time.Duration(10) * time.Second

	//================
	// Get auth token

	token, err := internal.GetAuthToken(projectID)
	if err != nil {
		log.Error(err)
	}
	log.Info(token)

	//================
	// Find notes
	//================

	notes, err := internal.FindNotesForProject(projectID)
	if err != nil {
		log.Error(err)
	}
	log.Info(notes)

	//================
	// Create note
	//================

	if len(notes) == 0 {
		note1, err := internal.CreateNote(projectID)
		if err != nil {
			log.Error(err)
		}
		log.Info(note1)
	}

	//===============================
	// Find occurrences for criteria
	//===============================

	occurrences1, err := internal.FindOccurrencesForCriteria(projectID,
		"vulnerabilities-tutorial-image",
		"sha256:ecc6b82ae27e3f41ff9685fc2b23fc1984ed8746d506c1715bf355036c230aad",
		"VULNERABILITY",
		"MEDIUM")

	if err != nil {
		log.Error(err)
	}
	log.Info(occurrences1)

	occurrences2, err := internal.FindOccurrencesForCriteria(projectID,
		"vulnerabilities-tutorial-image",
		"sha256:ecc6b82ae27e3f41ff9685fc2b23fc1984ed8746d506c1715bf355036c230aad",
		"ATTESTATION",
		"")
	if err != nil {
		log.Error(err)
	}
	log.Info(occurrences2)

	//===================
	// Create occurrence
	//===================

	if false {
		occurrence1, err := internal.CreateOccurrence(projectID)
		if err != nil {
			log.Error(err)
		}
		log.Info(occurrence1)
	}

	//================
	// Poll
	//================

	occ1, err := internal.PollDiscoveryOccurrenceFinished(resourceURL, projectID, timeout)
	if err != nil {
		log.Error(err)
	}

	occ2, err := internal.FindVulnerabilityOccurrencesForImage(resourceURL, projectID)
	if err != nil {
		log.Error(err)
	}

	log.Info(occ1)
	log.Info(occ2)

	//==========

	occurrenceID := "03698593-f06a-45de-8c22-01936d258124"
	occ3, err := internal.GetOccurrence(occurrenceID, "explorer-273804")
	if err != nil {
		log.Error(err)
	}
	log.Info(occ3)

	err = internal.GetDiscoveryInfo(resourceURL, projectID)
	if err != nil {
		log.Error(err)
	}
}
