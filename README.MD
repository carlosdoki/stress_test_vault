# Vault Integration with k6 Load Testing

This script demonstrates integration with HashiCorp Vault using k6 for load testing. It simulates authentication with Vault using AppRole and encryption/decryption operations with the Transit secrets engine.

## Prerequisites

Before running this script, ensure you have:

- k6 installed (https://k6.io/docs/getting-started/installation/)
- Access to a HashiCorp Vault instance (local or remote)
- AppRole credentials (ROLE_ID and SECRET_ID) for authentication
- Optional: Namespace setup in Vault, if required

## Environment Variables

Make sure to set the following environment variables:

- `VAULT_ADDR`: URL of your Vault instance (default: http://127.0.0.1:8200)
- `ROLE_ID`: Role ID for AppRole authentication
- `SECRET_ID`: Secret ID for AppRole authentication
- `TRANSIT_KEY_NAME`: Name of the Transit key in Vault for encryption/decryption (default: my-key)
- `NAMESPACE`: Vault namespace if using (optional)

## Usage

```bash
k6 run --out statsd vault_test.js
```
