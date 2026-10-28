# Deploying Entity 360 to Azure Container Apps

Hand-off guide. Target cost: about $0 at light use (consumption plan, scale to zero, image on GitHub Container Registry, no Log Analytics workspace).

## What gets created
| Item | Name | Notes |
|---|---|---|
| Resource group | `rg-e360` (westus3) | Holds everything below; delete it to remove the deployment |
| Container Apps environment | `cae-e360` | Consumption, `--logs-destination none` (no paid workspace) |
| Container app | `app-e360` | System-assigned managed identity, external HTTPS ingress on 8080, 0-1 replicas, 0.25 vCPU / 0.5 GiB |
| Key Vault permission | Key Vault Crypto User on `kv-e360-auth-xxxxx/keys/entity360-auth` | The vault uses Azure RBAC; the script falls back to an access policy (keys get+sign, certificates get) for vaults that don't |
| Redirect URI | `https://<fqdn>/auth/callback` | Appended to app registration; `http://localhost:3600/auth/callback` is kept |

No secrets are stored in the app. The certificate key never leaves Key Vault: the app gets a Key Vault token from its managed identity and asks the vault to sign the sign-in assertion.

## Prerequisites (checked by `C:\path\to\scripts\Test-E360DeployPrereqs.ps1`, read-only)
Run it first: `C:\path\to\scripts\Test-E360DeployPrereqs.ps1` (exit 0 = no FAIL). Build and deploy scripts run it automatically and stop on FAIL (`-SkipPrereqs` to bypass).

| Item | Required | Why |
|---|---|---|
| PowerShell | 5.1 or 7+ | Scripts are parse-checked on both |
| Windows | Win10 21H2 (build 19044)+ | Docker Desktop / WSL2 |
| Docker Desktop | **running**, engine 23.0+, **Linux containers** mode, buildx | BuildKit default builder; image is Linux (node:22-alpine) |
| Disk | 10 GB free | Image build cache |
| Azure CLI | 2.60+ (containerapp extension optional) | `az containerapp` env/ingress/identity commands used by the deploy script |
| Azure sign-in | admin@contoso.com, subscription "Free Azure Trial" enabled | Target subscription |
| Azure rights | Owner/Contributor + Owner/User Access Administrator | Create resources + Key Vault role assignment |
| Entra rights | App owner or Application/Cloud App/Global Administrator | Append redirect URI |
| Key Vault | `kv-e360-auth-xxxxx`, key `entity360-auth` | Assertion signing |
| Node.js / npm | 22+ | Local `npm test` (engines >=22) |
| git | any; `safe.directory C:/src` set | Repo is owned by Administrators |
| Network | HTTPS to ghcr.io, login.microsoftonline.com, management.azure.com | Push, sign-in, ARM |
| ghcr login | `docker login ghcr.io` (PAT with write:packages) | Push only |

## 1. Build and push the image
Use the helper; it runs the checks, sets the tag itself and builds from the repo folder, so commands cannot run out of order:
```powershell
C:\path\to\scripts\Build-E360Image.ps1                 # dry run: prints the docker commands
C:\path\to\scripts\Build-E360Image.ps1 -Apply          # build  ghcr.io/your-org/entity-360:<yyyyMMdd-HHmm> + :latest
docker login ghcr.io -u sectechtalk                 # once; PAT with write:packages
C:\path\to\scripts\Build-E360Image.ps1 -Apply -Push    # build + push
```
The image contains only `server/`, `public/` and production dependencies (`.env`, certificates, `.backups`, `.runtime`, tests are excluded by `.dockerignore`). It runs as the non-root `node` user.

Registry access: either make the package **public** on GitHub (Packages > entity-360 > Package settings > Change visibility; the code holds no secrets), or keep it private and pass a read-only PAT (`read:packages`) with `-GhcrUser`/`-GhcrToken`; the script stores it as a Container App secret and never prints it.

## 2. Deploy
Deploys always pin an immutable dated tag (`yyyyMMdd-HHmm`, or the legacy `yyyyMMddHHmm`), never `:latest`. `:latest` is mutable, so Container Apps sees an unchanged image string, creates no new revision, and rollback is ambiguous. The script refuses `:latest`, an untagged image and any non-dated tag.
```powershell
cd C:\path\to\scripts
.\Deploy-E360ContainerApp.ps1                     # prereq check, then dry run: resolves and prints the newest dated tag, changes nothing
.\Deploy-E360ContainerApp.ps1 -Apply              # deploy the newest dated tag in GHCR, then verify
.\Deploy-E360ContainerApp.ps1 -Apply -Image ghcr.io/your-org/entity-360:<yyyyMMdd-HHmm>   # a specific tag
# private image:  .\Deploy-E360ContainerApp.ps1 -Apply -GhcrUser sectechtalk -GhcrToken (Read-Host -AsSecureString)
# lock to your IP: add -AllowedIp 203.0.113.10/32
```
Before updating, the script checks that the tag exists in GHCR and is pullable anonymously, and records its digest. If the app already runs that exact image it changes nothing and still runs the checks. On an existing app only the image is updated; use `-Reprovision` to re-run the provisioning steps.

After `-Apply` it verifies and prints a pass/fail table: a new revision was created (or the image was already current), the revision is Healthy with 100% traffic, and `/auth/login` returns 302 to `login.microsoftonline.com`. It exits with code 1 on any FAIL and prints the rollback command. Every changed deploy is appended to `C:\path\to\scripts\logs\e360-deploy-history.json` (outside any repo).
## 3. Verify
- `az containerapp show -g rg-e360 -n app-e360 --query properties.configuration.ingress.fqdn -o tsv`
- Open `https://<fqdn>` (first request after idle takes several seconds: cold start from zero).
- Sign in: expect app-role gating. The E360 MFA Conditional Access prompt is enforced only if plan step 1.7 is switched to On (last logged state: report-only). Billing is denied unless you are in `sg-e360-billing`; activation through PIM applies only once plan step 1.8 is done.
- Logs: `az containerapp logs show -g rg-e360 -n app-e360 --follow` (console stream; there is no stored log history without a workspace).

## Runtime notes
- Sessions are in memory. With max 1 replica this is consistent, but sessions end when the app scales to zero or restarts; users simply sign in again. Do not raise max replicas without adding a shared session store.
- Hosted mode is switched on by `PUBLIC_BASE_URL`: the app trusts the ingress proxy, marks the session cookie `Secure`, accepts only that host (plus localhost for probes), and uses `<base>/auth/callback` as redirect URI. Local use is unchanged (127.0.0.1:3600, az login token).
- "Collect this computer": the local collector works only when the browser and server run on the same PC (localhost). In the hosted app it would read the container, not the user's PC, so use snapshot import as the hosted fallback. The target design for device data is Intune Remediations (plan Phase 4.6, design doc section 13).

## Costs (Microsoft list prices, not a quote)
Consumption plan free grant per subscription per month: 180,000 vCPU-seconds, 360,000 GiB-seconds, 2 million requests. Idle at zero replicas costs nothing. No ACR (~$5/mo) and no Log Analytics ingestion. The $10 budget alert `alert-10-dollar` stays as a backstop.

## Custom domain (later, not scripted)
Add a CNAME `e360.contoso.com` -> `<fqdn>` and TXT `asuid.e360` (value from `az containerapp show ... --query properties.customDomainVerificationId`), then `az containerapp hostname add` and `az containerapp hostname bind --validation-method CNAME` (free managed certificate). Then set `PUBLIC_BASE_URL=https://e360.contoso.com` and add that callback to the app registration.

## Rollback
- Previous image: `.\Deploy-E360ContainerApp.ps1 -Rollback` (dry run), then `-Rollback -Apply`. It redeploys the previous image recorded by the last deploy and runs the same verification. Or by hand: `az containerapp update -n app-e360 -g rg-e360 --image ghcr.io/your-org/entity-360:<older dated tag>`
- Remove everything: `.\Deploy-E360ContainerApp.ps1 -Remove` (dry run) then `-Remove -Apply` (removes the redirect URI, the Key Vault permission, and `rg-e360`; the vault and app registration are kept).
- Code changes for hosting are backed up in `.backups\*.pre-aca-20261023`.

