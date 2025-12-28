# Vault Plugin Auth OCI
Vault auth plugin for Oracle Cloud Infrastructure.

## Overview

This plugin enables authentication to HashiCorp Vault using Oracle Cloud Infrastructure (OCI) identity credentials. It supports two authentication modes:

1. **Instance Principal** (default): For Vault running inside OCI
2. **API Key**: For Vault running outside OCI (on-premises, AWS, GCP, etc.)

## Configuration

### Running Vault Inside OCI (Instance Principal)

When Vault runs on an OCI compute instance, it can use instance principal authentication to verify client credentials. This is the default mode and requires minimal configuration:

```bash
vault write auth/oci/config \
    home_tenancy_id=ocid1.tenancy.oc1..aaaaaaaexample
```

Or explicitly specify instance mode:

```bash
vault write auth/oci/config \
    home_tenancy_id=ocid1.tenancy.oc1..aaaaaaaexample \
    auth_mode=instance
```

### Running Vault Outside OCI (API Key)

When Vault runs outside OCI, configure it with API key authentication:

```bash
vault write auth/oci/config \
    home_tenancy_id=ocid1.tenancy.oc1..aaaaaaaexample \
    auth_mode=apikey \
    tenancy_ocid=ocid1.tenancy.oc1..aaaaaaaexample \
    user_ocid=ocid1.user.oc1..bbbbbbbbexample \
    fingerprint=aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99 \
    region=us-phoenix-1 \
    private_key=@$HOME/.oci/oci_api_key.pem
```

**Note**: Use the `@` prefix to read the private key from a file. This prevents the key from appearing in your shell history.

#### Generating OCI API Keys

1. In the OCI Console, navigate to your user settings
2. Under "API Keys", click "Add API Key"
3. Download the private key and note the fingerprint
4. Use these credentials to configure the Vault plugin

#### Required OCI IAM Permissions

The API key user must have the following permissions:
- `inspect users`
- `inspect groups`
- `inspect dynamic-groups`
- `use authentication-delegation`

### Configuration Reference

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `home_tenancy_id` | string | Yes | The tenancy OCID. Only entities from this tenancy can authenticate. |
| `auth_mode` | string | No | Authentication mode: `instance` (default) or `apikey` |
| `tenancy_ocid` | string | Conditional | Tenancy OCID (required when `auth_mode=apikey`) |
| `user_ocid` | string | Conditional | User OCID (required when `auth_mode=apikey`) |
| `fingerprint` | string | Conditional | API key fingerprint (required when `auth_mode=apikey`) |
| `private_key` | string | Conditional | PEM-encoded private key (required when `auth_mode=apikey`) |
| `private_key_passphrase` | string | No | Passphrase for encrypted private keys (optional) |
| `region` | string | Conditional | OCI region, e.g., `us-phoenix-1` (required when `auth_mode=apikey`) |

### Reading Configuration

```bash
vault read auth/oci/config
```

**Note**: Sensitive fields (`private_key`, `private_key_passphrase`) are redacted in the output.

## Troubleshooting

### Instance Principal Error

If you see: `Unable to create Instance Principal provider`, this typically means:
- Vault is not running on an OCI instance
- **Solution**: Configure API key authentication using the instructions above

### API Key Authentication Failed

If you see: `API key authentication requires tenancy_ocid, user_ocid, fingerprint, private_key, and region`:
- Ensure all required fields are provided when using `auth_mode=apikey`

### Invalid Private Key Format

If you see: `private_key must be in PEM format`:
- Ensure the private key is in PEM format with headers like `-----BEGIN RSA PRIVATE KEY-----`
- Use the `@` prefix to read from a file: `private_key=@/path/to/key.pem`

## Acceptance tests

The acceptance tests can only be run from an OCI instance.

If you are running this code on an OCI instance, you can run them directly with `make testacc`.
You will need to set the following environtment variables:
* `HOME_TENANCY_ID` to the tenancy you are running under (or your root tenancy ID)
* `ROLE_OCID_LIST` to a comma-separated list of group OCIDs to at least two groups. At least one should be a dynamic group that contains the instance, and another should be an identity group that contains your user.

For example:

```sh
make testacc HOME_TENANCY_ID=ocid1.tenancy.oc1..aaaaaaaasomecharacter ROLE_OCID_LIST=ocid1.group.oc1..aaaaaaaasomecharacters OCI_GO_SDK_DEBUG=info VAULT_LOG_LEVEL=debug
```

### Terraform

You can run the acceptance tests with terraform as well.

You will need an [OCI](https://signup.cloud.oracle.com) account.

You need to generate and download a private key in your account settings.
This should give you a private key file, the fingerprint, your tenancy OCID, and your user OCID.

Using those, you can run the acceptance tests via:

```sh
cd tests/terraform
# download your private key to this directory
terraform init
terraform apply \
  -var "fingerprint=YOURFINGERPRINT" \
  -var "tenancy_ocid=YOUR_TENANCY_OCID" \
  -var "user_ocid=YOUR_USER_OCID" \
  -var "private_key_path=YOUR_PRIVATE_KEY" \
  -var "region=YOUR_REGION"
```

This downloads the current `main` branch from GitHub and runs the tests on an OCI instance.
It takes about 5 minutes.

Don't forget to destroy the resources when you are done:

```sh
terraform destroy \
  -var "fingerprint=YOURFINGERPRINT" \
  -var "tenancy_ocid=YOUR_TENANCY_OCID" \
  -var "user_ocid=YOUR_USER_OCID" \
  -var "private_key_path=YOUR_PRIVATE_KEY" \
  -var "region=YOUR_REGION"
```

