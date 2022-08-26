package ingestion

import (
	config_proto "www.velocidex.com/golang/velociraptor/config/proto"
	crypto_proto "www.velocidex.com/golang/velociraptor/crypto/proto"
	"www.velocidex.com/golang/velociraptor/logging"
)

func (self ElasticIngestor) HandleEnrolment(
	config_obj *config_proto.Config,
	message *crypto_proto.VeloMessage) error {

	csr := message.CSR
	if csr == nil {
		return nil
	}

	client_id, err := self.crypto_manager.AddCertificateRequest(config_obj, csr.Pem)
	if err != nil {
		logger := logging.GetLogger(config_obj, &logging.FrontendComponent)
		logger.Error("While enrolling %v: %v", client_id, err)
		return err
	}

	return nil
}
