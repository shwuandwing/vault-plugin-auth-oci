// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import (
	"context"
	"fmt"
	"sync"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/common/auth"
)

// operationPrefixOCI is used as a prefix for OpenAPI operation id's.
const operationPrefixOCI = "oci"

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b, err := Backend()
	if err != nil {
		return nil, err
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

type backend struct {
	*framework.Backend

	// Lock to make changes to authClient entries
	authClientMutex sync.RWMutex

	// The client used to authenticate with OCI Identity
	authenticationClient *AuthenticationClient
}

func Backend() (*backend, error) {
	b := &backend{}

	b.Backend = &framework.Backend{
		Help: backendHelp,
		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				"login/*",
			},
		},
		Paths: []*framework.Path{
			pathLogin(b),
			pathLoginRole(b),
			pathRole(b),
			pathListRoles(b),
			pathConfig(b),
		},
		BackendType: logical.TypeCredential,
	}

	return b, nil
}

// getOrCreateAuthClient atomically gets or creates an authentication client.
// Returns the client under lock to prevent race conditions with Invalidate.
func (b *backend) getOrCreateAuthClient(ctx context.Context, storage logical.Storage) (*AuthenticationClient, error) {

	b.authClientMutex.Lock()
	defer b.authClientMutex.Unlock()

	// Return existing client if available
	if b.authenticationClient != nil {
		return b.authenticationClient, nil
	}

	// Read configuration to determine auth mode
	config, err := b.getOCIConfig(ctx, storage)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var configProvider common.ConfigurationProvider

	// Default to instance principal if no config or auth_mode not specified
	if config == nil || config.AuthMode == "" || config.AuthMode == "instance" {
		configProvider, err = b.createInstancePrincipalProvider()
	} else if config.AuthMode == "apikey" {
		configProvider, err = b.createAPIKeyProvider(config)
	} else {
		return nil, fmt.Errorf("invalid auth_mode: %s", config.AuthMode)
	}

	if err != nil {
		return nil, err
	}

	// Create the authentication client
	authenticationClient, err := NewAuthenticationClientWithConfigurationProvider(configProvider)
	if err != nil {
		b.Logger().Debug("Unable to create authenticationClient", "err", err)
		return nil, fmt.Errorf("unable to create authenticationClient: %w", err)
	}

	b.authenticationClient = &authenticationClient

	return b.authenticationClient, nil
}

// createInstancePrincipalProvider creates an instance principal configuration provider
func (b *backend) createInstancePrincipalProvider() (common.ConfigurationProvider, error) {
	ip, err := auth.InstancePrincipalConfigurationProvider()
	if err != nil {
		b.Logger().Debug("Unable to create InstancePrincipalConfigurationProvider", "err", err)
		return nil, fmt.Errorf("unable to create Instance Principal provider. This error typically occurs when Vault is not running on an OCI instance. To run Vault outside OCI, configure API key authentication: vault write auth/oci/config auth_mode=apikey tenancy_ocid=... user_ocid=... fingerprint=... region=... private_key=@key.pem. Original error: %w", err)
	}
	return ip, nil
}

// createAPIKeyProvider creates an API key configuration provider
func (b *backend) createAPIKeyProvider(config *OCIConfigEntry) (common.ConfigurationProvider, error) {
	// Validate required fields
	if config.TenancyOCID == "" || config.UserOCID == "" ||
		config.Fingerprint == "" || config.PrivateKey == "" || config.Region == "" {
		return nil, fmt.Errorf("API key authentication requires tenancy_ocid, user_ocid, fingerprint, private_key, and region")
	}

	var passphrasePtr *string
	if config.PrivateKeyPassphrase != "" {
		passphrasePtr = &config.PrivateKeyPassphrase
	}

	provider := common.NewRawConfigurationProvider(
		config.TenancyOCID,
		config.UserOCID,
		config.Region,
		config.Fingerprint,
		config.PrivateKey,
		passphrasePtr,
	)

	return provider, nil
}

// Invalidate cached clients whenever the configuration changes
func (b *backend) Invalidate(ctx context.Context, key string) {
	// Reset the auth client to force recreation with new config
	if key == "config" {
		b.authClientMutex.Lock()
		defer b.authClientMutex.Unlock()

		b.authenticationClient = nil
	}
}

const backendHelp = `
The OCI Auth plugin enables authentication and authorization using OCI Identity credentials. 

The OCI Auth plugin authorizes using roles. A role is defined as a set of allowed policies for specific entities. 
When an entity such as a user or instance logs in, it requests a role. 
The OCI Auth plugin checks whether the entity is allowed to use the role and which policies are associated with that role. 
It then assigns the given policies to the request.

The goal of roles is to restrict access to only the subset of secrets that are required, 
even if the entity has access to many more secrets. This conforms to the least-privilege security model.
`
