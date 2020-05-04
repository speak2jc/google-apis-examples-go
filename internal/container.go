package internal

import (
	"cloud.google.com/go/container"
	"context"
	"fmt"
	log "github.com/sirupsen/logrus"
)

func FindCluster(projectID string, clusterID string, zone string) (*container.Resource, error) {
	ctx := context.Background()
	client, err := container.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	cluster, err := client.Cluster(ctx, zone, clusterID)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	log.Info(cluster)
	return cluster, nil
}

func FindClustersForProject(projectID string, zone string) ([]*container.Resource, error) {
	ctx := context.Background()
	client, err := container.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	clusters, err := client.Clusters(ctx, zone)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	log.Info(clusters)
	return clusters, nil
}

func GetIpForCluster(projectID string, clusterID string) (*string, error) {
	ctx := context.Background()
	client, err := container.NewClient(ctx, projectID)
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	clusters, err := client.Clusters(ctx, "-")
	if err != nil {
		return nil, fmt.Errorf("NewClient: %v", err)
	}
	var cluster *container.Resource
	for _, clstr := range clusters {
		if clstr.Name == clusterID {
			cluster = clstr
		}
	}
	if cluster == nil {
		return nil, fmt.Errorf("Cluster not found: %s", clusterID)
	}

	return &cluster.Endpoint, nil
}
