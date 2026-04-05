META: MARK-CONFIDENTIAL
# StellaraeSecure
 
StellaraeSecure is a set of tools and resources designed to enhance the security of internal applications, such as our email services, git server, etc. 

It currently will provide:
- A staff account database, which will be used to manage access to apps and services and to provide a single source of truth for staff information.
- an OAuth2 server, which will be used to provide secure authentication and authorization for our internal applications.
- a set of libraries to be shared across all public stellarae applications to provide secure login with a single StellaSecure account. (With OAuth support for apps like github, google, etc.)
- A 2FA system, which will be used to provide an additional layer of security for our internal applications. This will be implemented using TOTP, and will be integrated with the staff account database and the OAuth2 server, we will not provide an authenticator app at this time. 
- Hardware security keys (or browser based, like proton pass, etc.) will be supported as a second factor or as a passwordless login method.

## About
StellaraeSecure is a group of projects in a unified repository, each project can be found in their own directory. The projects are:
- `staffdb`: The staff account database (and user accounts)
- `oauth2`: The OAuth2 server
- `lib`: The shared libraries for public stellarae applications
- `2fa`: The 2FA system (Server, client libraries are in `lib`)
- `hsk`: The hardware security key support (Server (generation and validation), client libraries are in `lib`)
- `admin`: The admin panel for managing staff accounts, 2FA, and hardware security keys.
- `docs`: A GitHub pages site for documentation and guides on how to use and integrate with StellaraeSecure.

## Can I use StellaraeSecure on my site?
Yes! Whether you want to integrate with our OAuth2 server to have an official SSO option by us, or if you want to use out code to run your own instance of the server, you are free to do so within the bounds of the MIT license. 

### How can I link to your server?
You can link to our server by using the following URL: `https://secure.stellarae.dev/oauth2/public` in your OAuth2 client configuration, then create an application at `https://secure.stellarae.dev/admin` to get your client ID and secret.

You MUST have a StellaraeSecure account to create an application, and MUST have 2FA via either TOTP or a hardware key.
Only staff members may use secure.stellarae.dev/oauth2/staff, which is the staff-only instance of the OAuth2 server.

## Can OAuth2 clients use the 2FA system?
If a client is configured to require 2FA, then users will be prompted to set up either a TOTP 2FA method or a hardware security key. Once they have set up their 2FA method, they will be required to use it when logging in to any application that requires 2FA.

There is no way to directly use the official 2FA system.

There is no public API for our 2FA system, but you can run your own server and use the client libraries in `lib` to integrate with it.

Current implementation status:
- Dedicated standalone `2fa` service is now available for TOTP and HSK bootstrap flows.
- `oauth2` can enforce second-factor readiness through the `2fa` service (`TOTP OR HSK`) when configured.
- Legacy bootstrap endpoints in `staffdb` remain available during migration.
- OpenAPI 3.1 contracts are published in `docs/openapi/` for `staffdb`, `oauth2`, and `2fa`.
- Operations runbooks and monitoring/SLO guidance are published in `docs/operations.html`.
- Metrics endpoints are available at `/metrics` for `staffdb`, `oauth2`, and `2fa`.

## Architecture
StellaraeSecure is built using a microservices architecture, with each project being its own service that can be deployed and scaled independently. The services communicate with each other using REST APIs, and all data is stored in a central database.

The 2FA server cannot obtain any personal information, and the OAuth2 server cannot obtain any 2FA information, this is to ensure that even if one service is compromised, the other service will still be secure. Furthermore, each server get assigned a randomised API key on startup or every 24 hours, along with a new encryption key for any data it needs to store, which is then decrypted and re-encrypted with the database's master key. Making any compromised service's data useless to an attacker without the master key, which is stored in a seperate device with no network access save for a secure connection to the database for key rotation that is only one way (The storage device can only send keys to the DB, it cannot receive any data or read any data from the DB).

### Overkill?
Probably, but hey, at least it's (hopefully) secure.

## Containerized Deployment

The repository now includes a root multi-service Docker Compose stack for:
- `staffdb` on port `3000`
- `oauth2` on port `4000`
- `admin` on port `8080`

### Quick start (live-deployment testing)

1. Copy the compose environment template:

```bash
cp .env.compose.example .env.compose
```

2. Start the full stack:

```bash
docker compose --env-file .env.compose up -d --build
```

3. Verify service health:

```bash
curl http://127.0.0.1:3000/healthz
curl http://127.0.0.1:4000/healthz
curl http://127.0.0.1:8080/healthz
```

4. Stop the stack:

```bash
docker compose down
```

### Architecture targeting

- The default compose platform is controlled by `STELLARAE_DOCKER_PLATFORM`.
- For ARM/RISC test devices, set this to `linux/arm64` or `linux/riscv64` (when supported by the host toolchain/base images).
- For AMD64/x86_64 production simulation, use:

```bash
STELLARAE_DOCKER_PLATFORM=linux/amd64 docker compose --env-file .env.compose up -d --build
```

You can also apply production defaults (enforced permission mode + amd64 platform) with:

```bash
docker compose --env-file .env.compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build
```

### Multi-arch image build (for registries)

Build and publish multi-platform images with Docker Buildx:

```bash
docker buildx build --platform linux/amd64,linux/arm64 -f staffdb/Dockerfile -t ghcr.io/<org>/stellarae-staffdb:latest staffdb --push
docker buildx build --platform linux/amd64,linux/arm64 -f oauth2/Dockerfile -t ghcr.io/<org>/stellarae-oauth2:latest oauth2 --push
docker buildx build --platform linux/amd64,linux/arm64 -f admin/Dockerfile -t ghcr.io/<org>/stellarae-admin:latest admin --push
```

Automated release publishing is also available via GitHub Actions:

- Workflow: `.github/workflows/release-images.yml`
- Trigger: push tag matching `v*` (for example `v0.2.0`) or manual dispatch
- Output: multi-arch GHCR images for `staffdb`, `oauth2`, `2fa`, and `admin`

Release governance:

- Tags are validated against semantic format (`vMAJOR.MINOR.PATCH`) before publishing.
- `CHANGELOG.md` must include a matching `## [vX.Y.Z]` entry for tag-based releases.

## CI Quality and Security Gates

- `.github/workflows/backend-ci.yml`: Rust test matrix for `oauth2`, `staffdb`, and `2fa`
- `.github/workflows/openapi-ci.yml`: OpenAPI contract validation/linting
- `.github/workflows/security-ci.yml`: dependency audit (`cargo audit`) + filesystem security scan (Trivy)
- `.github/workflows/containers-ci.yml`: compose validation and multi-arch container build checks

## Operational Automation Scripts

- `scripts/ops/backup.sh`: snapshots service volumes to compressed backups
- `scripts/ops/restore.sh <backup-dir>`: restores snapshots to service volumes
- `scripts/release/validate-tag.sh <tag>`: enforces semantic release tags and changelog entry

## Contributing
While contributions are welcome, we ask that you understand that it can take a long amount of time for a PR to be reviewed and merged. The sensitive nature of this project means that we have to be very careful about what code we merge, and we have to thoroughly review every line of code that is added to the project.

Contributions that contain ANY binary files will be automatically rejected, add a build script like a normal person if things must be compiled. This is to prevent any malicious code from being added to the project without our knowledge.

## Hack us!
There is no bug bounty, but if you want to try to find a vulnerability please use <\servicename>.hackme.stellarae.dev. It runs the same build number but is seperate from the production servers and therefore has no data or accounts. If you find a vulnerability, please report it to us at security@stellarae.dev.

<sub>Please use our PGP key when reporting vulnerabilities.</sub>

## License
StellaraeSecure is licensed under the MIT License. See the LICENSE file for more information or visit https://opensource.org/licenses/MIT.

<sub>&copy; 2026 Stellarae. Licensed under the MIT License.</sub>