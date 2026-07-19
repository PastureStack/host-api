package util

import (
	"github.com/PastureStack/host-api/config"
	"github.com/PastureStack/host-api/platformapi"
)

func GetPlatformClient() (*platformapi.Client, error) {
	apiURL := config.Config.PlatformURL
	accessKey := config.Config.PlatformAccessKey
	secretKey := config.Config.PlatformSecretKey

	if apiURL == "" || accessKey == "" || secretKey == "" {
		return nil, nil
	}

	apiClient, err := platformapi.NewClient(platformapi.ClientOpts{
		URL:       apiURL,
		AccessKey: accessKey,
		SecretKey: secretKey,
	})
	if err != nil {
		return nil, err
	}
	return apiClient, nil
}
