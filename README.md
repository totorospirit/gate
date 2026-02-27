# Gate

Simple, self-hosted forward authentication. Protect any web service behind a shared access code.

No OIDC. No OAuth. No passkeys. Just codes.

## What is Gate?

Gate is a lightweight forward auth service that sits between your reverse proxy and your applications. Users enter an access code to get a session cookie, and your proxy validates every request through Gate.

- **Single binary** — one Go binary, one SQLite file, one container
- **Zero complexity** — no identity providers, no user databases, just access codes
- **Works everywhere** — Traefik, Caddy, Nginx, or any proxy with forward auth support
- **Beautiful login page** — dark theme, responsive, i18n (English, Russian, Japanese)
- **Admin panel** — manage codes, sessions, and view audit logs
- **Production ready** — rate limiting, CSRF protection, bcrypt hashing, audit logging

## Quick Start

### Docker (recommended)

```bash
docker run -d \
  --name gate \
  -p 3000:3000 \
  -v gate-data:/data \
  -e ADMIN_CODE=my-secret-admin-code \
  -e COOKIE_DOMAIN=.example.com \
  -e BASE_URL=https://auth.example.com \
  ghcr.io/totorospirit/gate:latest
```

### Docker Compose

```yaml
services:
  gate:
    image: ghcr.io/totorospirit/gate:latest
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - ADMIN_CODE=my-secret-admin-code
      - BASE_URL=https://auth.example.com
      - COOKIE_DOMAIN=.example.com
    volumes:
      - gate-data:/data

volumes:
  gate-data:
```

### From Source

```bash
git clone https://github.com/totorospirit/gate.git
cd gate
go build -o gate .
ADMIN_CODE=my-secret-code ./gate
```

## How It Works

```
User → Reverse Proxy → Gate (verify) → ✓ 200 → Application
                                      → ✗ 302 → Login Page → Enter Code → Cookie Set → Redirect Back
```

1. User visits `app.example.com`
2. Reverse proxy calls Gate's verify endpoint
3. If no valid session cookie → redirect to Gate login page
4. User enters access code → Gate validates, creates session cookie
5. User is redirected back to `app.example.com`
6. Cookie is shared across `*.example.com` via `COOKIE_DOMAIN`

## Configuration

All configuration is via environment variables.

| Variable | Default | Description |
|---|---|---|
| `ADMIN_CODE` | *(required on first run)* | Initial admin access code |
| `PORT` | `3000` | Listen port |
| `BASE_URL` | `http://localhost:3000` | Public URL of Gate |
| `COOKIE_DOMAIN` | *(empty)* | Domain for cookie sharing (e.g. `.example.com`) |
| `COOKIE_SECRET` | *(auto-generated)* | HMAC secret for cookie signing |
| `SESSION_TTL` | `168h` | Session lifetime (Go duration) |
| `DB_PATH` | `./data/gate.db` | SQLite database path |
| `APP_NAME` | `Gate` | Name shown on login page |
| `LOGO_URL` | *(empty)* | Optional logo URL for login page |
| `RATE_LIMIT` | `5` | Max login attempts per IP per minute |
| `LOCKOUT_AFTER` | `10` | Lock IP after N total failures |
| `LOCKOUT_DURATION` | `15m` | How long to lock out an IP |
| `TRUSTED_PROXIES` | `127.0.0.1/32,10.0.0.0/8,...` | CIDRs to trust for X-Forwarded-* headers |

## Proxy Integration

### Traefik

Add Gate as a forward auth middleware. Protect any service by adding the middleware label.

**docker-compose.yml:**

```yaml
services:
  gate:
    image: ghcr.io/totorospirit/gate:latest
    environment:
      - ADMIN_CODE=my-secret-code
      - BASE_URL=https://auth.example.com
      - COOKIE_DOMAIN=.example.com
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.gate.rule=Host(`auth.example.com`)"
      - "traefik.http.routers.gate.entrypoints=websecure"
      - "traefik.http.routers.gate.tls.certresolver=letsencrypt"
      - "traefik.http.services.gate.loadbalancer.server.port=3000"
      # Define the middleware
      - "traefik.http.middlewares.gate-auth.forwardauth.address=http://gate:3000/api/verify/traefik"
      - "traefik.http.middlewares.gate-auth.forwardauth.trustForwardHeader=true"
      - "traefik.http.middlewares.gate-auth.forwardauth.authResponseHeaders=X-Gate-User,X-Gate-Role"

  # Any service you want to protect:
  myapp:
    image: myapp:latest
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.myapp.rule=Host(`myapp.example.com`)"
      - "traefik.http.routers.myapp.middlewares=gate-auth@docker"
```

### Caddy

**Caddyfile:**

```
auth.example.com {
    reverse_proxy gate:3000
}

myapp.example.com {
    forward_auth gate:3000 {
        uri /api/verify/caddy
        copy_headers {
            X-Gate-User
            X-Gate-Role
        }
    }
    reverse_proxy myapp:8080
}
```

### Nginx

**nginx.conf:**

```nginx
# Gate itself
server {
    listen 443 ssl;
    server_name auth.example.com;

    location / {
        proxy_pass http://gate:3000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Protected service
server {
    listen 443 ssl;
    server_name myapp.example.com;

    # Auth subrequest
    location = /_auth {
        internal;
        proxy_pass http://gate:3000/api/verify/nginx;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Forwarded-Host $host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-Uri $request_uri;
        proxy_set_header Cookie $http_cookie;
    }

    location / {
        auth_request /_auth;
        # On 401, redirect to login
        error_page 401 = @login;

        proxy_pass http://myapp:8080;
    }

    location @login {
        return 302 https://auth.example.com/login?redirect=$scheme://$host$request_uri;
    }
}
```

## API Endpoints

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/login` | GET | - | Login page |
| `/login` | POST | - | Submit access code |
| `/logout` | POST | Session | End session |
| `/api/verify` | GET | Cookie | Generic forward auth |
| `/api/verify/traefik` | GET | Cookie | Traefik forward auth |
| `/api/verify/caddy` | GET | Cookie | Caddy forward auth |
| `/api/verify/nginx` | GET | Cookie | Nginx auth_request |
| `/api/stats` | GET | Admin | Server statistics |
| `/admin` | GET | Admin | Admin dashboard |
| `/admin/codes` | GET | Admin | Manage access codes |
| `/admin/sessions` | GET | Admin | View active sessions |
| `/admin/audit` | GET | Admin | Audit log |
| `/admin/settings` | GET | Admin | View settings |
| `/health` | GET | - | Health check |

## Access Codes

Codes support:

- **Roles**: `admin` (full access + admin panel) or `user` (auth only)
- **Expiry**: optional expiration date
- **Max uses**: optional usage limit
- **Revocation**: disable a code without deleting it

The initial admin code is set via `ADMIN_CODE` env var and is only created on the very first run (when the database is empty). After that, manage codes through the admin panel.

## Security

- Access codes are hashed with **bcrypt** before storage
- Session cookies are **HMAC-signed**, HttpOnly, Secure, SameSite=Lax
- **CSRF protection** on all state-changing forms
- **Rate limiting**: configurable per-IP attempts per minute
- **IP lockout**: configurable threshold and duration
- **Audit logging**: all auth events recorded with IP and user agent
- **Trusted proxies**: only accept X-Forwarded-* from configured CIDRs

## Comparison

| Feature | Gate | PocketID | Authelia |
|---|---|---|---|
| Setup complexity | Minimal (2 env vars) | Moderate | Complex |
| Auth method | Access codes | Passkeys/OIDC | Multi-factor |
| User management | Codes only | Full user accounts | Full user accounts |
| Dependencies | None (single binary) | None | Redis + SMTP |
| Best for | Shared access, small teams | Personal SSO | Enterprise SSO |

Gate is intentionally simple. If you need full user management, SSO, or MFA, look at Authelia or PocketID. If you just need to put a code on a door, Gate is for you.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

### Development

```bash
# Run locally
go run .

# Build
go build -o gate .

# Build Docker image
docker build -t gate .
```

## License

MIT
