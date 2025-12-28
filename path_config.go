// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// These constants store the configuration keys
const (
	HomeTenancyIdConfigName = "home_tenancy_id"
)

func pathConfig(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "config",

		DisplayAttrs: &framework.DisplayAttributes{
			OperationPrefix: operationPrefixOCI,
		},

		Fields: map[string]*framework.FieldSchema{
			HomeTenancyIdConfigName: {
				Type:        framework.TypeString,
				Description: "The tenancy id of the account.",
			},
			"auth_mode": {
				Type:        framework.TypeString,
				Description: "Authentication mode: 'instance' (default) or 'apikey'. Use 'instance' when Vault runs inside OCI, 'apikey' when running outside OCI.",
				Default:     "instance",
			},
			"tenancy_ocid": {
				Type:        framework.TypeString,
				Description: "Tenancy OCID for API key authentication (required when auth_mode=apikey).",
			},
			"user_ocid": {
				Type:        framework.TypeString,
				Description: "User OCID for API key authentication (required when auth_mode=apikey).",
			},
			"fingerprint": {
				Type:        framework.TypeString,
				Description: "API key fingerprint (required when auth_mode=apikey).",
			},
			"private_key": {
				Type:        framework.TypeString,
				Description: "PEM-encoded private key content (required when auth_mode=apikey).",
			},
			"private_key_passphrase": {
				Type:        framework.TypeString,
				Description: "Passphrase for encrypted private key (optional).",
			},
			"region": {
				Type:        framework.TypeString,
				Description: "OCI region (e.g., us-phoenix-1, required when auth_mode=apikey).",
			},
		},

		ExistenceCheck: b.pathConfigExistenceCheck,

		Operations: map[logical.Operation]framework.OperationHandler{
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigCreateUpdate,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigCreateUpdate,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationVerb: "configure",
				},
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
				DisplayAttrs: &framework.DisplayAttributes{
					OperationSuffix: "configuration",
				},
			},
		},

		HelpSynopsis:    pathConfigSyn,
		HelpDescription: pathConfigDesc,
	}
}

// Establishes dichotomy of request operation between CreateOperation and UpdateOperation.
// Returning 'true' forces an UpdateOperation, CreateOperation otherwise.
func (b *backend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.getOCIConfig(ctx, req.Storage)
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

// setOCIConfig creates or updates a config in the storage.
func (b *backend) setOCIConfig(ctx context.Context, s logical.Storage, configEntry *OCIConfigEntry) error {
	if configEntry == nil {
		return fmt.Errorf("config is not found")
	}

	entry, err := logical.StorageEntryJSON("config", configEntry)
	if err != nil {
		return err
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// getOCIConfig returns the properties set on the given config.
// This method also does NOT check to see if a config upgrade is required. It is
// the responsibility of the caller to check if a config upgrade is required and,
// if so, to upgrade the config
func (b *backend) getOCIConfig(ctx context.Context, s logical.Storage) (*OCIConfigEntry, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result OCIConfigEntry
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, err
	}

	return &result, nil
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	configEntry, err := b.getOCIConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if configEntry == nil {
		return nil, nil
	}

	responseData := map[string]interface{}{
		HomeTenancyIdConfigName: configEntry.HomeTenancyId,
	}

	// Add auth_mode if set
	if configEntry.AuthMode != "" {
		responseData["auth_mode"] = configEntry.AuthMode
	}

	// Add API key fields if configured (redact sensitive data)
	if configEntry.AuthMode == "apikey" {
		responseData["tenancy_ocid"] = configEntry.TenancyOCID
		responseData["user_ocid"] = configEntry.UserOCID
		responseData["fingerprint"] = configEntry.Fingerprint
		responseData["region"] = configEntry.Region
	}

	return &logical.Response{
		Data: responseData,
	}, nil
}

// Create a Config
func (b *backend) pathConfigCreateUpdate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	homeTenancyId := data.Get(HomeTenancyIdConfigName).(string)
	if strings.TrimSpace(homeTenancyId) == "" {
		return logical.ErrorResponse("Missing homeTenancyId"), nil
	}

	configEntry, err := b.getOCIConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if configEntry == nil && req.Operation == logical.UpdateOperation {
		return logical.ErrorResponse("The specified config does not exist"), nil
	}

	// Get auth_mode, defaulting to "instance" for backwards compatibility
	authMode := data.Get("auth_mode").(string)
	if authMode == "" {
		authMode = "instance"
	}

	// Validate auth_mode
	if authMode != "instance" && authMode != "apikey" {
		return logical.ErrorResponse("auth_mode must be 'instance' or 'apikey'"), nil
	}

	configEntry = &OCIConfigEntry{
		HomeTenancyId: homeTenancyId,
		AuthMode:      authMode,
	}

	// If API key mode, validate and store credentials
	if authMode == "apikey" {
		tenancyOCID := data.Get("tenancy_ocid").(string)
		userOCID := data.Get("user_ocid").(string)
		fingerprint := data.Get("fingerprint").(string)
		privateKey := data.Get("private_key").(string)
		region := data.Get("region").(string)
		privateKeyPassphrase := data.Get("private_key_passphrase").(string)

		// Validate required fields
		if tenancyOCID == "" || userOCID == "" || fingerprint == "" ||
			privateKey == "" || region == "" {
			return logical.ErrorResponse(
				"API key authentication requires tenancy_ocid, user_ocid, fingerprint, private_key, and region",
			), nil
		}

		// Validate private key format (should contain PEM markers)
		if !strings.Contains(privateKey, "BEGIN") || !strings.Contains(privateKey, "PRIVATE KEY") {
			return logical.ErrorResponse("private_key must be in PEM format"), nil
		}

		configEntry.TenancyOCID = tenancyOCID
		configEntry.UserOCID = userOCID
		configEntry.Fingerprint = fingerprint
		configEntry.PrivateKey = privateKey
		configEntry.PrivateKeyPassphrase = privateKeyPassphrase
		configEntry.Region = region
	}

	if err := b.setOCIConfig(ctx, req.Storage, configEntry); err != nil {
		return nil, err
	}

	b.InvalidateKey(ctx, "config")
	var resp logical.Response

	return &resp, nil
}

// Delete a Config
func (b *backend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if err := req.Storage.Delete(ctx, "config"); err != nil {
		return nil, err
	}

	b.InvalidateKey(ctx, "config")
	return nil, nil
}

// Struct to hold the information associated with an OCI config
type OCIConfigEntry struct {
	HomeTenancyId string `json:"home_tenancy_id"`

	// Authentication mode: "instance" (default) or "apikey"
	AuthMode string `json:"auth_mode,omitempty"`

	// API Key fields (used when AuthMode = "apikey")
	TenancyOCID          string `json:"tenancy_ocid,omitempty"`
	UserOCID             string `json:"user_ocid,omitempty"`
	Fingerprint          string `json:"fingerprint,omitempty"`
	PrivateKey           string `json:"private_key,omitempty"`
	PrivateKeyPassphrase string `json:"private_key_passphrase,omitempty"`
	Region               string `json:"region,omitempty"`
}

const pathConfigSyn = `
Manages the configuration for the Vault Auth Plugin.
`

const pathConfigDesc = `
The home_tenancy_id configuration is the Tenant OCID of your OCI Account. Only login requests from entities present in this tenant are accepted.

Example:

vault write /auth/oci/config home_tenancy_id=myocid
`
