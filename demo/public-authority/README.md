# Public WebFinger handle-authority deployment artifact

This directory is the deployment-ready artifact for the Followee
Milestone 5 public demonstration: the **same** minimal handle authority
exercised by the local black-box test suite (`followee handle serve`,
implemented in `src/webfinger/authority.rs`), placed behind HTTPS on a
provider-assigned domain. Nothing here is a second implementation — the
binary, configuration format, and JRD semantics are exactly those the
tests pin (`tests/handle_deploy_artifact.rs` serves this directory's
example configuration and probes it with the production WebFinger
client; `tests/handle_railway_packaging.rs` runs the shipped container
entrypoint end to end).

The authority is **immutable and stateless**: it serves a reviewed
static configuration and public signed record bytes. It needs no
database, holds no private key, and emits no secret in any log, startup
object, or command line.

Two deployment paths are provided. **Railway is the canonical
reproducible path**; the provider-neutral VPS path is retained for
operators who already control a server. Both serve the identical
configuration format, command surface, and JRD semantics.

| File | Purpose |
| --- | --- |
| `authority.example.json` | Configuration template (replace domain and identities) |
| `alice.cose` | Example bootstrap record: the exact Appendix B.4 test envelope |
| `railway/Dockerfile` | Reproducible multi-stage container build (pinned toolchain, `--locked`) |
| `railway/entrypoint.sh` | Container start: binds `0.0.0.0:$PORT`, explicit public base URI |
| `railway/authority.json` | **Bootstrapped Railway public artifact**: maps `demo@handle-authority-production.up.railway.app` to the demonstration DID |
| `railway/demo.cose` | The bootstrapped public signed record baked into the image (284 bytes, SHA-256 below) |
| `railway/alice.cose` | Leftover template-era copy of the Appendix B.4 example record; no longer referenced by the Dockerfile, configuration, or tests |
| `../../railway.json` | Railway config-as-code pointing at the Dockerfile |
| `../../.dockerignore` | Bounded container build context |
| `Caddyfile` | VPS: TLS-terminating reverse proxy (automatic HTTPS) |
| `nginx.conf` | VPS: equivalent nginx TLS-termination snippet |
| `followee-handle.service` | VPS: hardened systemd unit for the authority process |

Two kinds of material live here and must not be confused:

- **Generic example/template material** — `authority.example.json` and
  `alice.cose` (plus the now-unreferenced `railway/alice.cose` copy) use
  the published Appendix B test vectors (public test material; never for
  a real identity). The B.4 record's signed `alsoKnownAs` claims
  `acct:alice@example.com`, and a signed claim is immutable — no
  configuration, environment variable, or provider setting can change it
  — so this material can never pass the deployment gate for a
  provider-assigned domain. It exists for local tests, documentation,
  and as a template for other operators.
- **The bootstrapped Railway public artifact** — `railway/authority.json`
  and `railway/demo.cose` carry the completed Milestone 5 identity
  bootstrap and **pass the production predeployment gate as checked in**
  (pinned by
  `deploy_artifact_railway_bootstrap_passes_the_production_deployment_gate`).
  Durable audit facts:

  | Fact | Value |
  | --- | --- |
  | Public domain | `handle-authority-production.up.railway.app` |
  | Handle | `demo@handle-authority-production.up.railway.app` |
  | DID | `did:flw:zQmV2sbfh2M5kHBAa9G1svAdh54bZqGKLUE3YJpBHj8qb4R` |
  | Record | `railway/demo.cose`, 284 bytes |
  | Record SHA-256 | `9ece97525772992cdf049cb0387958e93daa4999913a9324ed91db78f513d927` |

  The private seed files remain solely in local operator custody outside
  this repository; only the public configuration and signed public
  record are checked in or baked into the image.

  **Deployed and live-probed.** On 2026-08-13 this artifact was deployed
  to Railway (project `85fd8851-bae0-4e23-b003-5bdf2cb9f6f7`, service
  `8e2ce593-d677-47a0-91c1-2d1a3cd1ac4a`, initial accepted deployment
  `799fbd4b-e605-4fa2-9116-a080213e0226`) and the complete section 5
  public probe set passed against
  `https://handle-authority-production.up.railway.app/`: startup
  reported the exact base URI, domain, `developmentMode: false`, one
  handle and one record on `0.0.0.0:8080`; the raw WebFinger probe
  answered HTTP 200 with `application/jrd+json`,
  `Access-Control-Allow-Origin: *`, the exact subject, and exactly one
  Followee DID relation carrying the DID above; an unknown handle
  returned 404 and a missing `resource` parameter 400, each with an
  empty body; the production `followee handle resolve` discovered the
  DID and selected a verified fresh admissible Root winner; the
  production `followee handle verify` exited 0 with
  `handleVerified: true` and inverse status `matched`; and the live
  `/record/demo` response was 284 bytes, SHA-256
  `9ece97525772992cdf049cb0387958e93daa4999913a9324ed91db78f513d927`,
  byte-identical to the checked-in `railway/demo.cose`.

No purchased domain or ICP dependency is required or involved.

## 1. What the service must provide (specification section 10)

- `GET /.well-known/webfinger?resource=acct%3A<local>%40<domain>` →
  `200`, `Content-Type: application/jrd+json`,
  `Access-Control-Allow-Origin: *`, body `{"subject": "<exact requested
  resource>", "links": [{"rel": "https://w3id.org/followee/rel/did",
  "href": "did:flw:..."}, ...]}` with exactly one Followee DID link;
  unknown resources → `404`; missing or malformed `resource` parameter
  → `400`.
- Optionally `GET /record/<local>` → `200`,
  `Content-Type: application/cose`, one complete Identity Record
  (bootstrap publisher only — clients always verify locally).
- HTTPS is terminated by the provider (Railway) or reverse proxy (VPS);
  the authority process itself listens on plain HTTP behind it and, with
  an `https://` base URI, runs in conforming mode.
- The advertised base URI (used for bootstrap `record` links) comes only
  from operator configuration or the provider's domain variable — never
  from a request header.
- ASCII-case variants of one local part are never assignable to
  different DIDs: the configuration loader rejects such a configuration
  outright, and unlisted variants return `404`.

## 2. Configure (both paths)

Configuration rules (all enforced at load; the process refuses to start
otherwise):

- `version` is `1`; unknown fields are rejected;
- `domain` is the canonical lowercase ASCII IDNA domain the public
  service is reached at — it must equal the provider-assigned domain;
- every `local` and alias is 1–64 ASCII characters from
  `A–Z a–z 0–9 . _ -` and unique; two locals differing only by ASCII
  case must map to the same DID (aliases), or loading fails;
- every `did` is a canonical `did:flw` v1 DID;
- every `record` path (relative to the configuration file) must contain
  a complete Identity Record that verifies for that entry's DID.

### Predeployment consistency gate (both paths)

`followee handle serve --config <config.json> --check` validates the
configuration completely and then requires, for **every** local served
with a bootstrap record (aliases included), that the record verifies
through the production verifier for the mapped DID **and** that its
signed `alsoKnownAs` claims the exact canonical `acct:<local>@<domain>`
resource the authority would serve. The configuration maps that handle
back to the same DID by construction, so a passing check aligns both
directions of section 10.4 before anything is published. It prints one
machine-readable report and exits nonzero (`deploymentInconsistent`) on
any mismatch — run it before every deployment; deploy only on exit 0:

```bash
cargo build --release
target/release/followee handle serve --config <config.json> --check
```

## 3. Canonical path: Railway (reproducible container)

Architecture: Railway builds `railway/Dockerfile` from the repository
(pinned `rust:1.97.1` toolchain, `cargo build --release --locked`),
terminates TLS on its assigned `*.up.railway.app` domain, injects
`PORT`, and forwards plain HTTP to the container. The entrypoint runs
exactly `followee handle serve --config /app/authority.json --listen
0.0.0.0:$PORT --base-uri <public base>`, where the base is
`FOLLOWEE_BASE_URI` if set, else `https://$RAILWAY_PUBLIC_DOMAIN/`.
`exec` makes the authority PID 1, so Railway's SIGTERM produces the
tested clean shutdown. The image contains the binary, the reviewed
public configuration, and the public record bytes — nothing else.

Deployment is a **two-phase identity bootstrap** (performed by the
operator; **not** performed by this repository's tooling), because the
provider assigns the domain first and the demonstration identity must
then sign a record claiming a handle under exactly that domain.

> **Status:** both phases below are complete for
> `handle-authority-production.up.railway.app`, the artifact is checked
> in beside this file, it passes the consistency gate, **and the
> deployment plus the complete section 5 live probes have passed** (see
> the evidence block in the overview above). The steps are retained
> verbatim so the bootstrap is reproducible for any other domain.

**Phase 1 — obtain the domain.**

```bash
# Create the Railway project from the repository root (railway.json
# selects the Dockerfile automatically), then assign the public domain:
railway init          # or create the project in the dashboard
railway up            # first deploy serves the template: fine, it maps
                      # nothing under the real domain yet
railway domain        # note the assigned domain, e.g.
DOMAIN=followee-demo.up.railway.app
```

**Phase 2 — bootstrap the demonstration identity and redeploy.**

```bash
# 1. Generate a dedicated demonstration identity LOCALLY. Keep both seed
#    files outside the repository and outside any build context — they
#    must never enter git, the image, or Railway:
followee identity create \
    --root-key ~/followee-demo/root.seed \
    --revocation-key ~/followee-demo/revocation.seed \
    --identity ~/followee-demo/identity.json

# 2. Sign a fresh public record whose alsoKnownAs claims the EXACT
#    Railway handle (contact.json: {"alsoKnownAs":["acct:demo@$DOMAIN"]}):
followee record sign-root \
    --identity ~/followee-demo/identity.json \
    --key ~/followee-demo/root.seed \
    --contact contact.json \
    --out demo/public-authority/railway/demo.cose

# 3. Replace the template configuration with the real one — public data
#    only (DID from identity.json, the assigned domain, the new record):
#    demo/public-authority/railway/authority.json:
#      {"version":1,"domain":"$DOMAIN","handles":[
#        {"local":"demo","did":"did:flw:z…","record":"demo.cose"}]}
#    and update the Dockerfile COPY lines if you renamed the record file.

# 4. Run the predeployment consistency gate; deploy ONLY on exit 0:
target/release/followee handle serve \
    --config demo/public-authority/railway/authority.json --check

# 5. Deploy the final artifact and run the public probes below:
railway up
```

`RAILWAY_PUBLIC_DOMAIN` is provided by Railway once the domain exists,
so no further variable is needed; setting `FOLLOWEE_BASE_URI` explicitly
overrides it. The service logs show the one startup object — verify
`baseUri`, `domain`, and `developmentMode: false` there. The deployed
artifact contains only the public identity/configuration and the signed
public record; the seed files stay in local operator custody.

The local packaging check (`cargo test --test
handle_railway_packaging`) proves this exact entrypoint honours `PORT`,
uses the production `handle serve` path, refuses to start without a
configured public base, serves the tested JRD semantics, and exits `0`
on SIGTERM.

### Future relay note (not part of Milestone 5)

A later **relay** deployment test on Railway would attach a persistent
volume mounted at `/data` and pass `--database /data/relay.sqlite` to
`followee relay serve`. The Milestone 5 handle authority is stateless
and must not be conflated with that profile: it mounts no volume and has
no database, and no relay deployment is claimed here.

## 4. Retained alternative: provider-neutral VPS

The authority binds loopback; Caddy or nginx terminates HTTPS for the
assigned domain and forwards to it. Same binary, same configuration
format, same probes.

### Option A — Caddy (automatic certificates)

`Caddyfile` (edit the domain):

```text
your-domain.example {
    reverse_proxy 127.0.0.1:8130
}
```

### Option B — nginx (certificates from the provider or certbot)

See `nginx.conf`; it proxies `/.well-known/webfinger` and `/record/` to
`127.0.0.1:8130`.

### The authority process

Run the same predeployment consistency gate first (deploy only on
exit 0), then run directly:

```bash
target/release/followee handle serve --config /etc/followee/authority.json --check
target/release/followee handle serve \
    --config /etc/followee/authority.json \
    --listen 127.0.0.1:8130 \
    --base-uri https://your-domain.example/
```

Or install `followee-handle.service` (edit paths and domain), then:

```bash
sudo systemctl enable --now followee-handle
```

`--base-uri` must be the public HTTPS base ending in `/`: it selects
conforming (non-development) mode and is used to construct the bootstrap
`record` link URLs inside served JRDs. The command prints exactly one
machine-readable startup object and shuts down cleanly on SIGINT or
SIGTERM.

## 5. Public acceptance probes (run after deployment, either path)

These commands constitute the external Milestone 5 acceptance gate and
are run only once the service is deployed (they need the public
Internet). The values below are the bootstrapped Railway artifact's;
substitute your own for any other deployment:

```bash
DOMAIN=handle-authority-production.up.railway.app
LOCAL=demo
DID=did:flw:zQmV2sbfh2M5kHBAa9G1svAdh54bZqGKLUE3YJpBHj8qb4R

# 1. Raw WebFinger probe: expect HTTP 200, Content-Type
#    application/jrd+json, Access-Control-Allow-Origin: *, subject
#    exactly acct:$LOCAL@$DOMAIN, and exactly one link with rel
#    https://w3id.org/followee/rel/did.
curl -si "https://$DOMAIN/.well-known/webfinger?resource=acct%3A$LOCAL%40$DOMAIN"

# 2. Unknown handle: expect HTTP 404.
curl -si "https://$DOMAIN/.well-known/webfinger?resource=acct%3Anobody%40$DOMAIN"

# 3. Malformed request (missing resource parameter): expect HTTP 400.
curl -si "https://$DOMAIN/.well-known/webfinger"

# 4. The production client, end to end (public HTTPS policy is the
#    default): discovery, exact-subject, link-cardinality, bootstrap.
target/release/followee handle resolve --handle "$LOCAL@$DOMAIN"

# 5. Inverse verification against the deployed record (its alsoKnownAs
#    contains acct:$LOCAL@$DOMAIN by the predeployment gate). The probe
#    ASSERTS success — merely running the command proves nothing. The
#    output and the followee process's exit status are captured
#    separately (a pipeline would not preserve the status without
#    pipefail), both are printed, the JSON is parsed, and Boolean
#    handleVerified must be exactly true. Failure is reported with a
#    false result, never by exiting the operator's shell.
probe5_output=$(target/release/followee handle verify \
    --handle "$LOCAL@$DOMAIN" --did "$DID" \
    --record demo/public-authority/railway/demo.cose)
probe5_status=$?
printf '%s\n' "$probe5_output"
echo "followee handle verify exit status: $probe5_status"
if [ "$probe5_status" -eq 0 ] && printf '%s' "$probe5_output" | python3 -c '
import json, sys
sys.exit(0 if json.load(sys.stdin).get("handleVerified") is True else 1)
'
then
    echo "PROBE 5 OK: exit status 0 and handleVerified true"
else
    echo "PROBE 5 FAILED"
    false
fi
```

Step 4 must report the mapped DID with `"status": "discovered"`; step 5
passes only when `followee handle verify` exits `0` **and** reports
`"handleVerified": true` — which requires the record to claim the exact
handle and the domain to map it back to the same DID. For probe 5,
`path/to/record.cose` is the deployed public record — for the
bootstrapped artifact, `demo/public-authority/railway/demo.cose`.

## 6. What this deployment never does

- It never holds or needs private keys, deployment credentials, or
  mutable state.
- It never marks anything "verified": clients verify records locally and
  perform their own inverse lookups.
- It never derives a served link or security decision from a request
  header: the public base URI is deployment configuration.
- Its disappearance or reassignment of a handle cannot change any
  follower's stored DID, cached verified identity, or sticky
  RootRevoked state — handles are replaceable presentation state over
  durable DIDs.
