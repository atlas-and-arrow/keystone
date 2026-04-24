# Keystone Licensing System

## Overview

Keystone provides AES-256-CBC encrypted license key validation with local and remote verification, domain locking, feature gating, and expiry management.

## License Key Format

License keys are AES-256-CBC encrypted, base64-encoded blobs. When decrypted, they contain JSON:

```json
{
    "id": "lic_abc123",
    "product": "walter",
    "domains": ["example.com", "staging.example.com"],
    "instances": 5,
    "expires": "2027-04-13",
    "issued": "2026-04-13",
    "features": ["pro-tools", "priority-support", "white-label"]
}
```

### Fields

| Field       | Type     | Description                           |
|-------------|----------|---------------------------------------|
| `id`        | string   | Unique license identifier             |
| `product`   | string   | Product slug (must match)             |
| `domains`   | array    | Allowed domains (supports wildcards)  |
| `instances` | int      | Max concurrent installations          |
| `expires`   | string   | Expiry date (Y-m-d format)            |
| `issued`    | string   | Issue date (Y-m-d format)             |
| `features`  | array    | Enabled feature slugs                 |

## Encryption

- **Algorithm**: AES-256-CBC
- **Key derivation**: SHA-256 hash of the shared secret (produces 256-bit key)
- **IV**: 16 random bytes, prepended to ciphertext before base64 encoding

### Generating a License Key

```php
$license_data = array(
    'id'        => 'lic_' . wp_generate_password( 8, false ),
    'product'   => 'walter',
    'domains'   => array( 'example.com', '*.example.com' ),
    'instances' => 5,
    'expires'   => '2027-04-13',
    'issued'    => date( 'Y-m-d' ),
    'features'  => array( 'pro-tools', 'priority-support' ),
);

$key = Keystone_License::encrypt_license( $license_data, 'your-secret-here' );
// Store $key as the license key
```

## Validation Flow

1. **Transient cache** — check `keystone_lic_{product}` transient; return cached result if present
2. **Local validation**:
   - Decrypt key with AES-256-CBC — fail = invalid
   - Verify product slug matches
   - Check expiry date (3-day grace period)
   - Check domain matches current site (wildcard support)
3. **Remote validation** (if server configured):
   - POST to `{server}/validate` with license_id, product, domain, site_url
   - Server validates instance count, revocation, etc.
   - If unreachable — trust local result
4. **Cache result**:
   - Full validation (remote success): 24 hours
   - Local-only (server unreachable): 1 hour
   - Invalid: 1 hour

## Domain Matching

- Exact match: `example.com`
- Wildcard: `*.example.com` matches `staging.example.com`, `dev.example.com`, and `example.com` itself
- Case-insensitive comparison

## Usage

### Basic License Check

```php
$license = Keystone::license( 'walter', array(
    'secret' => 'your-shared-secret',
));

if ( $license->is_licensed() ) {
    // Product is licensed
}
```

### Feature Gating

```php
if ( $license->is_enabled( 'pro-tools' ) ) {
    // Show pro tools
}
```

### License Info

```php
$license->expires();        // '2027-04-13'
$license->days_remaining(); // 365
$license->domains();        // ['example.com']
$license->features();       // ['pro-tools', 'priority-support']
$license->id();             // 'lic_abc123'
```

### Admin Notices

```php
$license->register_admin_notice();
// Automatically shows:
// - Warning if no key configured
// - Error if key is invalid
// - Warning if expiring within 30 days
```

### Clearing Cache

```php
$license->clear_cache(); // Clears transient and forces re-validation
```

## WordPress Options

License settings are stored in wp_options:

- `keystone_{product}_license_key` — The encrypted license key
- `keystone_{product}_license_server` — Remote validation server URL
- `keystone_{product}_license_secret` — Encryption secret

## Remote Validation Server

The remote server endpoint (`POST /validate`) receives:

```json
{
    "license_id": "lic_abc123",
    "product": "walter",
    "domain": "example.com",
    "site_url": "https://example.com"
}
```

Expected response:

```json
{
    "valid": true
}
```

Or on failure:

```json
{
    "valid": false,
    "reason": "License has been revoked."
}
```
