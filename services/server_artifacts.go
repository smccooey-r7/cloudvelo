package services

import (
	"errors"

	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	crypto_proto "www.velocidex.com/golang/velociraptor/crypto/proto"
	flows_proto "www.velocidex.com/golang/velociraptor/flows/proto"
)

var (
	g_artifact_service ServerArtifactsService = nil
)

func GetServerArtifactService() (ServerArtifactsService, error) {
	mu.Lock()
	defer mu.Unlock()

	if g_artifact_service == nil {
		return nil, errors.New("ServerArtifactsService not ready")
	}

	return g_artifact_service, nil
}

func RegisterServerArtifactsService(s ServerArtifactsService) {
	mu.Lock()
	defer mu.Unlock()

	g_artifact_service = s
}

type ServerArtifactsService interface {
	LaunchServerArtifact(
		config_obj *config_proto.Config,
		collection_context *flows_proto.ArtifactCollectorContext,
		tasks []*crypto_proto.VeloMessage) error
}
