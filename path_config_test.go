// Copyright © 2019, Oracle and/or its affiliates.
package ociauth

import (
	"context"
	"testing"

	"fmt"
	"os"

	"github.com/hashicorp/vault/sdk/logical"
)

func TestBackend_PathConfig(t *testing.T) {

	// Skip tests if we are not running acceptance tests
	if os.Getenv("VAULT_ACC") == "" {
		t.SkipNow()
	}

	var resp *logical.Response
	var err error
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Backend()
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}
	configPath := "config"

	configData := map[string]interface{}{
		HomeTenancyIdConfigName: "ocid1.tenancy.oc1..dummy",
	}

	configReq := &logical.Request{
		Operation: logical.CreateOperation,
		Storage:   config.StorageView,
		Data:      configData,
	}

	configReq.Path = configPath
	resp, err = b.HandleRequest(context.Background(), configReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Config creation failed. resp:%#v\n err:%v", resp, err)
	}

	// now read the config
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configReq.Path,
		Storage:   config.StorageView,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Read config failed. resp:%#v\n err:%v", resp, err)
	}

	// now try to update the config (should pass)
	configUpdate := map[string]interface{}{
		HomeTenancyIdConfigName: "ocid1.tenancy.oc2..dummy",
	}

	configReqUpdate := &logical.Request{
		Operation: logical.UpdateOperation,
		Storage:   config.StorageView,
		Data:      configUpdate,
	}

	configReqUpdate.Path = configPath
	resp, err = b.HandleRequest(context.Background(), configReqUpdate)
	if err != nil {
		t.Fatalf("bad: config update failed. resp:%#v\n err:%v", resp, err)
	}

	if resp != nil && resp.IsError() == true {
		t.Fatalf("Config update failed.")
	}

	// now try to delete the config
	resp, err = b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      configPath,
		Storage:   config.StorageView,
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("Config delete failed. resp:%#v\n err:%v", resp, err)
	}

	fmt.Println("All tests completed successfully")
}

func TestBackend_PathConfig_APIKey(t *testing.T) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	b, err := Backend()
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Setup(context.Background(), config); err != nil {
		t.Fatal(err)
	}

	// Test 1: Create config with API key mode
	t.Run("CreateConfigWithAPIKey", func(t *testing.T) {
		configData := map[string]interface{}{
			HomeTenancyIdConfigName: "ocid1.tenancy.oc1..aaaatest",
			"auth_mode":             "apikey",
			"tenancy_ocid":          "ocid1.tenancy.oc1..aaaatest",
			"user_ocid":             "ocid1.user.oc1..bbbbtest",
			"fingerprint":           "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
			"region":                "us-phoenix-1",
			"private_key": `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAtest
-----END RSA PRIVATE KEY-----`,
			"private_key_passphrase": "testpassphrase",
		}

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Storage:   config.StorageView,
			Data:      configData,
		})

		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("Config creation with API key failed. resp:%#v\n err:%v", resp, err)
		}
	})

	// Test 2: Read config and verify redaction
	t.Run("ReadConfigVerifyRedaction", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   config.StorageView,
		})

		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("Read config failed. resp:%#v\n err:%v", resp, err)
		}

		// Verify sensitive fields are redacted

		if _, exists := resp.Data["private_key"]; exists {
			t.Fatalf("private_key should be redacted, got: %v", resp.Data["private_key"])
		}
		if _, exists := resp.Data["private_key_passphrase"]; exists {
			t.Fatalf("private_key_passphrase should be redacted, got: %v", resp.Data["private_key_passphrase"])
		}

		// Verify non-sensitive fields are present
		if resp.Data["auth_mode"] != "apikey" {
			t.Fatalf("auth_mode should be 'apikey', got: %v", resp.Data["auth_mode"])
		}
		if resp.Data["tenancy_ocid"] != "ocid1.tenancy.oc1..aaaatest" {
			t.Fatalf("tenancy_ocid mismatch")
		}
	})

	// Test 3: Invalid auth_mode
	t.Run("InvalidAuthMode", func(t *testing.T) {
		configData := map[string]interface{}{
			HomeTenancyIdConfigName: "ocid1.tenancy.oc1..aaaatest",
			"auth_mode":             "invalid",
		}

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Storage:   config.StorageView,
			Data:      configData,
		})

		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatalf("Expected error for invalid auth_mode")
		}
	})

	// Test 4: Missing required API key fields
	t.Run("MissingAPIKeyFields", func(t *testing.T) {
		configData := map[string]interface{}{
			HomeTenancyIdConfigName: "ocid1.tenancy.oc1..aaaatest",
			"auth_mode":             "apikey",
			"tenancy_ocid":          "ocid1.tenancy.oc1..aaaatest",
			// Missing user_ocid, fingerprint, region, private_key
		}

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Storage:   config.StorageView,
			Data:      configData,
		})

		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatalf("Expected error for missing required API key fields")
		}
	})

	// Test 5: Invalid private key format
	t.Run("InvalidPrivateKeyFormat", func(t *testing.T) {
		configData := map[string]interface{}{
			HomeTenancyIdConfigName: "ocid1.tenancy.oc1..aaaatest",
			"auth_mode":             "apikey",
			"tenancy_ocid":          "ocid1.tenancy.oc1..aaaatest",
			"user_ocid":             "ocid1.user.oc1..bbbbtest",
			"fingerprint":           "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99",
			"region":                "us-phoenix-1",
			"private_key":           "not-a-valid-pem-key",
		}

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Storage:   config.StorageView,
			Data:      configData,
		})

		if err == nil && (resp == nil || !resp.IsError()) {
			t.Fatalf("Expected error for invalid private key format")
		}
	})

	// Test 6: Backwards compatibility - no auth_mode defaults to instance
	t.Run("BackwardsCompatibility", func(t *testing.T) {
		configData := map[string]interface{}{
			HomeTenancyIdConfigName: "ocid1.tenancy.oc1..aaaatest",
			// No auth_mode specified
		}

		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "config",
			Storage:   config.StorageView,
			Data:      configData,
		})

		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("Config creation without auth_mode failed. resp:%#v\n err:%v", resp, err)
		}

		// Read back and verify auth_mode defaults to instance
		resp, err = b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.ReadOperation,
			Path:      "config",
			Storage:   config.StorageView,
		})

		if err != nil || (resp != nil && resp.IsError()) {
			t.Fatalf("Read config failed. resp:%#v\n err:%v", resp, err)
		}

		// Should either have auth_mode=instance or no auth_mode field (both acceptable)
		if authMode, ok := resp.Data["auth_mode"]; ok && authMode != "instance" {
			t.Fatalf("Expected auth_mode to be 'instance' or absent, got: %v", authMode)
		}
	})

	fmt.Println("API key config tests completed successfully")
}
