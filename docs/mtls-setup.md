# mTLS Authentication Setup

Guardian supports mutual TLS (mTLS) for certificate-based authentication in production. This ensures that only services with valid client certificates can call the Guardian API.

## How It Works

Guardian doesn't terminate TLS itself. A reverse proxy (Nginx, Envoy, Traefik) handles TLS termination, validates the client certificate against your CA, and passes certificate info to Guardian via HTTP headers.

```
Client (with cert)
    ↓ (mTLS)
Reverse Proxy (Nginx/Envoy)
    ↓ (validates cert, adds headers)
Guardian API
    ↓ (reads X-Client-Cert-Subject header)
    ↓ (verifies CN against allowed list)
    ↓ (proceeds with evaluation)
```

## Configuration

Set these environment variables on the Guardian instance:

```bash
GUARDIAN_MTLS_ENABLED=true
GUARDIAN_MTLS_HEADER=X-Client-Cert-Subject     # header name from proxy
GUARDIAN_MTLS_ALLOWED_CNS=terraform-runner,k8s-admission,deploy-bot
```

- `GUARDIAN_MTLS_ENABLED=true` — activates mTLS verification
- `GUARDIAN_MTLS_HEADER` — the header your proxy sets with the cert subject
- `GUARDIAN_MTLS_ALLOWED_CNS` — comma-separated list of allowed Common Names (empty = any valid cert)

## Nginx Configuration

```nginx
server {
    listen 443 ssl;
    server_name guardian.internal;

    # Server certificate
    ssl_certificate     /etc/nginx/certs/server.crt;
    ssl_certificate_key /etc/nginx/certs/server.key;

    # Client certificate verification
    ssl_client_certificate /etc/nginx/certs/ca.crt;
    ssl_verify_client on;

    location / {
        proxy_pass http://localhost:8000;

        # Pass client cert info to Guardian
        proxy_set_header X-Client-Cert-Subject $ssl_client_s_dn;
        proxy_set_header X-Client-Cert-Fingerprint $ssl_client_fingerprint;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
```

## Testing

```bash
# With a valid client cert
curl --cert client.crt --key client.key \
  https://guardian.internal/v1/health

# Without a cert (should get 401)
curl https://guardian.internal/v1/health
# → {"detail": "mTLS required: no client certificate found"}
```

## Combined Auth (API Key + mTLS)

Set both `GUARDIAN_API_KEY` and `GUARDIAN_MTLS_ENABLED=true`. Requests must provide both a valid API key AND a valid client certificate.
