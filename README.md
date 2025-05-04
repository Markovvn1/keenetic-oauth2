<div align="center">
  <img src=".github/logo.svg" height="124px"/><br/>
  <h1>Keenetic Router OAuth2 Proxy</h1>
  <p>Go-based HTTP reverse proxy to replace standard auth in Keenetic Web Interface with OAuth2/OIDC</p>
</div>

## 📝 About The Project

A Go-based HTTP reverse-proxy that fronts your Keenetic router’s web UI with an OAuth2/OIDC login layer, JMESPath-based role extraction, and automatic router session management for **Admin** and **Viewer** users.

> *The program was almost entirely written by ChatGPT o4-mini-high.*

#### Features

- **OIDC/OAuth2 authentication**
- **JMESPath** expression to map OIDC claims to `Admin` or `Viewer` roles
- Automatic **re-login** on `401 Unauthorized` from the router
- Kubernetes-friendly: `/healthz`, `/ready`, graceful shutdown, panic-recovery, timeouts
- Configurable via **environment variables** or flags

#### Prerequisites

- A Keenetic router with web management interface
- An OIDC-compliant Identity Provider (e.g. Keycloak)

## ⚡ Quick start

```bash
docker run -d \
  --name keen-proxy \
  -p 8080:8080 \
  -e SESSION_SECRET=$(openssl rand -base64 32 | head -c 32) \
  -e ROUTER_URL="http://192.168.1.1/" \
  -e ADMIN_USER="admin" \
  -e ADMIN_PASS="***" \
  -e OIDC_ISSUER="https://sso.example.com/realms/infra" \
  -e OAUTH2_CLIENT_ID="my-router" \
  -e OAUTH2_SECRET="***" \
  -e OAUTH2_REDIRECT="http://localhost:8080/oauth2/callback" \
  -e JMES_ROLE_QUERY="(contains(resource_access.\"my-router\".roles[], 'admin.my-router') && 'Admin') || (contains(resource_access.\"my-router\".roles[], 'viewer.my-router') && 'Viewer')" \
  ghcr.io/markovvn1/keenetic-oauth2:latest
```

Point your browser to http://localhost:8080/, authenticate via your OIDC provider, and enjoy seamless, role-based access to your Keenetic router.

## ⚙️ Configuration

All settings are read from environment variables (or flags of the same name). See the table below:

| Environment Variable | Required | Description                                                  |
| -------------------- | -------- | ------------------------------------------------------------ |
| `SESSION_SECRET`     | Yes      | 32-byte random secret for signing & encrypting session cookies |
| `ROUTER_URL`         | Yes      | Base URL of your Keenetic router                             |
| `ADMIN_USER`         | No       | Router admin username                                        |
| `ADMIN_PASS`         | No       | Router admin password                                        |
| `VIEWER_USER`        | No       | Router viewer username                                       |
| `VIEWER_PASS`        | No       | Router viewer password                                       |
| `OIDC_ISSUER`        | Yes      | OIDC issuer URL                                              |
| `OAUTH2_CLIENT_ID`   | Yes      | OAuth2 client identifier                                     |
| `OAUTH2_SECRET`      | Yes      | OAuth2 client secret                                         |
| `OAUTH2_REDIRECT`    | Yes      | OAuth2 redirect URI (callback)                               |
| `JMES_ROLE_QUERY`    | Yes      | [JMESPath](https://jmespath.org/) expression that returns `"Admin"` or `"Viewer"` from your ID token claims |
| `BIND_ADDRESS`       | No       | Address for the HTTP server to listen on (default: `:8080`)  |

## 📜 License

`Keenetic Router OAuth2 Proxy` is free and open-source software licensed under the [MIT License](LICENSE)
