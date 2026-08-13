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
| `railway/authority.json` | **Example/template** configuration baked into the image (must be replaced by the two-phase bootstrap below before final acceptance) |
| `railway/alice.cose` | Copy of the example record referenced by the template |
| `../../railway.json` | Railway config-as-code pointing at the Dockerfile |
| `../../.dockerignore` | Bounded container build context |
| `Caddyfile` | VPS: TLS-terminating reverse proxy (automatic HTTPS) |
| `nginx.conf` | VPS: equivalent nginx TLS-termination snippet |
| `followee-handle.service` | VPS: hardened systemd unit for the authority process |

The checked-in identities are the **published Appendix B test vectors**
(public test material; they must never be used for a real identity), and
the checked-in `alice.cose` is the exact Appendix B.4 envelope whose
signed `alsoKnownAs` claims `acct:alice@example.com`. A signed claim is
immutable: no configuration, environment variable, or provider setting
can change it. The checked-in files are therefore an **example/template
only** — they cannot satisfy a provider-assigned domain handle, the
predeployment consistency gate rejects them for public deployment
(pinned by `deploy_artifact_template_is_honestly_not_deployable_as_is`),
and final acceptance requires the two-phase bootstrap below with a
freshly signed record. No purchased domain or ICP dependency is required
or involved.

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
then sign a record claiming a handle under exactly that domain:

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
Internet). Replace the domain with the provider-assigned one:

```bash
DOMAIN=your-domain.example     # e.g. followee-demo.up.railway.app
LOCAL=alice

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
#    ASSERTS success: exit status 0 and handleVerified true — merely
#    running the command proves nothing.
target/release/followee handle verify --handle "$LOCAL@$DOMAIN" \
    --did "$DID" --record path/to/record.cose \
    | tee /dev/stderr | grep -q '"handleVerified":true' \
    && echo "PROBE 5 OK: handleVerified" \
    || { echo "PROBE 5 FAILED"; exit 1; }
```

Step 4 must report the mapped DID with `"status": "discovered"`; step 5
passes only when `followee handle verify` exits `0` **and** reports
`"handleVerified": true` — which requires the record to claim the exact
handle and the domain to map it back to the same DID. (`$LOCAL` and
`$DID` are the local and DID deployed in phase 2, e.g. `demo` and the
DID from `identity.json`.)

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
