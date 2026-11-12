# Ory Kratos v26.2.0: image and source assessment

Prepared by Centipod for the Ory Kratos maintainers, 12 November 2026.

We run Ory Kratos v26.2.0 in production for id.centipod.io and are grateful for the project. This report sets out what we found when we scanned the published image and reviewed the source, what we changed in our fork to reduce the exposure, and what we would suggest upstream. Everything here can be reproduced from the commands and references given.

## 1. Scope and method

| Item | Value |
| --- | --- |
| Version | Ory Kratos v26.2.0 (tag commit `9d7085948039ffb8960160d4979f71527b5cf4d5`, 20 March 2026) |
| Image | `oryd/kratos:v26.2.0@sha256:2a13bb8d362c7a7ae33bd7c0f5168aee46921f15c916a06346db91c06dc76643` (linux/amd64, Alpine variant) |
| Compared with | `ory/kratos` master at `b86338da0` (29 July 2026), the newest commit at the time of writing |
| Date | 12 November 2026 |
| Image scanner | Trivy 0.72.0, vulnerability scanner only, local database updated 12 November 2026 07:01 UTC |
| Source analysis | Centipod AI Quality Framework 9.7.0, Go rules, `service` profile, run against tag v26.2.0 (3025 findings), including its `go vet`, `staticcheck` and `go test` legs |
| Manual review | Every security-relevant finding group was checked or sampled by hand at v26.2.0; the results are marked below |

What was not done: no dynamic testing, no fuzzing, no penetration testing, and no review of Ory's hosted services. Database-backed tests ran against SQLite only. Tests that start Ory Hydra in Docker were not run (listed in section 5.3). Where we say a vulnerability is not reachable, that is a reading of the code paths, not a proof.

How the framework output was handled: the framework presents each finding as a question, not a verdict. About 59% of the 3025 findings (1798) sit in the generated Go SDK (`pkg/client-go`, `pkg/httpclient`) and a further 217 in test helpers. Several large rule groups (`GO-IDN-001`, `GO-IDN-003`, `GO-TSP-002`, `QLT-AGT-*`, `GO-RRM-004`, `GO-RRM-008`) describe how a generated client library should be shaped and do not apply to a server. We therefore report only what we confirmed by reading the code, and for each group we say what we judged a false positive and why.

## 2. Summary

Three things matter most. First, the published v26.2.0 image carries **4 CRITICAL and 72 HIGH** findings: the binary was built with Go 1.26.0, several modules (pgx, golang.org/x/net, x/crypto, grpc, go-jose, OpenTelemetry) are behind their fixed releases, and the runtime base is `alpine:3.20.0`, which Trivy reports as end of life. Master has fixed part of this (pgx, OpenTelemetry, and it has dropped the Docker and pgx v4 dependencies) but has not been released, and it still uses Alpine 3.20.0, go-jose v4.1.4, x/net v0.56.0 and grpc v1.82.1. With the small set of bumps in section 5 the same image drops to **0 CRITICAL and 4 HIGH**, and none of those four has a fixed release. Second, the CVE scan in CI scans an image built from `.docker/Dockerfile-build` (Debian and distroless), not `.docker/Dockerfile-alpine`, which is what goreleaser publishes, and it runs only on push, pull request and tag, never on a schedule; that is how an end-of-life base and new advisories against released tags go unnoticed. Third, the release pipeline depends on mutable references: none of the 54 GitHub Action references is pinned to a commit, the release job runs `ory/ci/releaser@master` with the signing password and registry credentials, and `.goreleaser.yml` includes its build template from, and runs a script from, the `master` branch of another repository. The source itself is in good shape for a project of this size; we confirmed a handful of real but low-severity defects (section 4).

## 3. Image findings

### 3.1 Counts per severity

Trivy 0.72.0, `--scanners vuln`, same database for both scans.

| Severity | Published: OS (Alpine 3.20.0) | Published: Go binary | Published: total | Centipod rebuild: total |
| --- | ---: | ---: | ---: | ---: |
| CRITICAL | 2 | 2 | **4** | **0** |
| HIGH | 13 | 59 | **72** | **4** |
| MEDIUM | 5 | 42 | 47 | 6 |
| LOW | 0 | 8 | 8 | 4 |
| UNKNOWN | 0 | 3 | 3 | 1 |

The rebuild (`centipod/kratos:v26.2.0-centipod.1`) is v26.2.0 with only the dependency, toolchain and base image changes described in section 5. Its OS layer (Alpine 3.24.4) has no findings at all; all 15 remaining findings are in the Go binary.

### 3.2 CRITICAL and HIGH in the published image

"Master" means `ory/kratos` master at `b86338da0`. For Go modules we read master's `go.mod` and scanned it with `trivy fs`. The Go standard library depends on the toolchain used to build a release, which master does not pin.

**Operating system packages (Alpine 3.20.0 base layer)**

| Package | Installed | Fixed | Advisories | Fixed on master |
| --- | --- | --- | --- | --- |
| libcrypto3, libssl3 | 3.3.6-r0 | 3.3.7-r0 | CRITICAL CVE-2026-31789; HIGH CVE-2026-28387, CVE-2026-28388, CVE-2026-28389, CVE-2026-28390 (counted for both packages: 2 CRITICAL, 8 HIGH) | No, master still uses `FROM alpine:3.20.0` |
| musl, musl-utils | 1.2.5-r1 | 1.2.5-r4 | HIGH CVE-2026-107891, CVE-2026-40200 (counted for both packages: 4 HIGH) | No |
| zlib | 1.3.1-r1 | 1.3.2-r0 | HIGH CVE-2026-22184 | No |

**Go binary `/usr/bin/kratos`**

| Module | Installed | Fixed | Advisories | Fixed on master |
| --- | --- | --- | --- | --- |
| github.com/jackc/pgx/v5 | v5.7.5 | v5.9.0 | CRITICAL CVE-2026-33815, CVE-2026-33816 (memory safety) | Yes (v5.10.0) |
| stdlib | 1.26.0 | 1.26.10 | 26 HIGH in crypto/x509, crypto/tls, net/http, net/url, net/mail, net, mime, encoding/asn1, encoding/xml, html/template and os.Root: CVE-2026-111943, CVE-2026-25679, CVE-2026-27137, CVE-2026-27145, CVE-2026-32280, CVE-2026-32281, CVE-2026-32283, CVE-2026-33810, CVE-2026-33811, CVE-2026-33814, CVE-2026-33818, CVE-2026-39820, CVE-2026-39821, CVE-2026-39822, CVE-2026-39836, CVE-2026-42499, CVE-2026-42504, CVE-2026-46600, CVE-2026-56853, CVE-2026-56858, CVE-2026-56859, CVE-2026-56860, CVE-2026-56862, CVE-2026-78667, CVE-2026-78669, CVE-2026-97031 | Not determined: `go.mod` says `go 1.26` with no `toolchain` line, so it depends on the Go version in the release environment |
| golang.org/x/crypto | v0.46.0 | v0.55.0 | 10 HIGH, all in `ssh` and `ssh/agent`: CVE-2026-39828, CVE-2026-39829, CVE-2026-39830, CVE-2026-39831, CVE-2026-39832, CVE-2026-39835, CVE-2026-42508, CVE-2026-46595, CVE-2026-46597, CVE-2026-56854 | Partly: master has v0.53.0, CVE-2026-56854 remains |
| golang.org/x/net | v0.48.0 | v0.62.0 | 7 HIGH in html, http2, idna and dns/dnsmessage: CVE-2026-25681, CVE-2026-27136, CVE-2026-33814, CVE-2026-39821, CVE-2026-46600, CVE-2026-78661, CVE-2026-78669 | Partly: master has v0.56.0, CVE-2026-78661 and CVE-2026-78669 remain |
| google.golang.org/grpc | v1.79.3 | v1.83.2 | 3 HIGH: GHSA-hrxh-6v49-42gf, CVE-2026-84304, CVE-2026-84445 | Partly: master has v1.82.1, CVE-2026-84304 and CVE-2026-84445 remain |
| golang.org/x/text | v0.32.0 | v0.41.0 | 2 HIGH: CVE-2026-56851, CVE-2026-56852 | Partly: master has v0.39.0, CVE-2026-56851 remains |
| golang.org/x/mod | v0.30.0 | v0.40.0 | 2 HIGH in sumdb: CVE-2026-56864, CVE-2026-56865 | No, master has v0.37.0 |
| github.com/go-jose/go-jose/v4 | v4.1.3 | v4.1.6 | 2 HIGH: CVE-2026-34986; CVE-2026-116587 (denial of service through crafted RSA parameters in JWKs) | Partly: master has v4.1.4, CVE-2026-116587 remains |
| github.com/go-jose/go-jose/v3 | v3.0.4 | v3.0.5 / none | 2 HIGH: CVE-2026-34986 (fixed in v3.0.5); CVE-2026-116587 (no v3 fix) | Partly: master has v3.0.5, CVE-2026-116587 remains |
| go.opentelemetry.io/otel, otel/sdk | v1.40.0 | v1.41.0 / v1.43.0 | 2 HIGH: CVE-2026-29181, CVE-2026-39883 | Yes (v1.44.0) |
| github.com/docker/docker | v28.3.3+incompatible | none | 2 HIGH: CVE-2026-41567, CVE-2026-42306 (both in the Docker daemon) | Yes, the module is no longer in master's build |
| github.com/jackc/pgproto3/v2 | v2.3.3 | none | 1 HIGH: CVE-2026-32286 (panic on a malicious DataRow from the server) | Yes, master no longer depends on the pgx v4 stack |

### 3.3 What remains after the rebuild, and why

| Module | Advisory | Why it remains | Our reading of exposure |
| --- | --- | --- | --- |
| github.com/docker/docker v28.3.3+incompatible | CVE-2026-41567, CVE-2026-42306 (HIGH) | No fixed release in the `+incompatible` line. It is linked into the server because `oryx/dbal/testhelpers.go` (not a `_test.go` file) imports `ory/x/sqlcon/dockertest`, which pulls in `ory/dockertest/v4` and the Docker client. | Both advisories are in the Docker daemon. Kratos only links client code and does not call it at runtime. Master has moved to `github.com/moby/moby/client`, but `oryx/dbal/testhelpers.go` still links the test container tooling into the production binary there. |
| github.com/go-jose/go-jose/v3 v3.0.5 | CVE-2026-116587 (HIGH) | No fixed v3 release. Pulled in by `oryx/jwksx` (`fetcher.go`, `generator.go`) and `oryx/josex`. | Kratos fetches key sets through `jwksx.FetcherNext`, which uses `lestrrat-go/jwx`, so we found no runtime path where v3 parses an untrusted key. The package is linked because `jwksx` is imported as a whole. This also remains on master. |
| github.com/jackc/pgproto3/v2 v2.3.3 | CVE-2026-32286 (HIGH) | No fixed release. Pulled in by `jackc/pgconn` v1, which `oryx/popx/transaction.go` and `oryx/sqlcon/error.go` import only to recognise PostgreSQL error types. | Connections use pgx v5, so the v2 decoder is not exercised; the advisory also needs a malicious database server. Master has already removed this dependency. |

The remaining MEDIUM findings are docker/docker (2), go-jose v3 (2), slack-go v0.13.1 (fixed in v0.23.1, which master has) and mongo-driver v1.17.4 (fixed in v1.17.7, which master has). The LOW findings are four OpenTelemetry v1.44.0 modules (CVE-2026-81870, fixed in v1.45.0); the UNKNOWN is the unmaintained `x/crypto/openpgp` package notice (GO-2026-5932), which Kratos does not import.

### 3.4 Image recommendations

1. **Cut a release from master** with the few bumps master still lacks. The branch `centipod/upstream-security` in our fork (section 5.4) is exactly that and nothing more: Go toolchain 1.26.11, go-jose/v4 v4.1.6, golang.org/x/net v0.62.0 (which moves x/crypto, x/text and x/mod past their fixes), grpc v1.83.2 and Alpine 3.24.4. On that branch `trivy fs` reports one HIGH in the server's Go modules (go-jose v3, no fix).
2. **Bump go-jose v4 to v4.1.6.** It is the one fixable HIGH on master that meets untrusted input: coreos/go-oidc uses it to parse ID tokens and key sets from external identity providers in the OIDC strategy.
3. **Pin the Go patch level** with a `toolchain go1.26.x` line in `go.mod`, so `setup-go` and the floating `golang:1.26` images cannot produce a release on an old patch level. The v26.2.0 binary reports Go 1.26.0.
4. **Move off Alpine 3.20.0 and rebuild base images regularly.** Alpine 3.20.0 is the first 3.20 point release and Trivy marks 3.20 as end of life. The Dockerfile already runs `apk upgrade`, so a scheduled rebuild of each supported tag would pick up base fixes without code changes.
5. **Items that remain even on master:** go-jose v3 (no fix; moving `oryx/jwksx` and `oryx/josex` to v4 would remove it) and the test container tooling linked into the server through `oryx/dbal/testhelpers.go` (moving those helpers into a test-only package or behind a build tag would take the Docker client out of the binary and its advisories out of every future scan).

## 4. Source findings

Line references are at tag v26.2.0. "Checked by hand" means we read every instance; "sampled" means we read a representative subset. "On master" says whether the same code is still present at `b86338da0`.

### 4.1 Overview of the framework output

| Area | Findings | In generated SDK | In test helpers | Our judgement |
| --- | ---: | ---: | ---: | --- |
| SDK shape rules (`GO-IDN-001`, `GO-IDN-003`, `GO-IDN-005`, `GO-TSP-002`) | 1329 | 986 | 39 | Not applicable to a server; see 4.3 |
| Resilience and resources (`GO-RRM-*`, `QLT-AGT-*`) | 176 | 12 | 88 | Mostly false positives; 4 confirmed defects |
| Suppressions (`GO-LSA-005`) | 25 | 0 | 6 | Real; 1 false positive; 2 hide real defects |
| Credentials, TLS, privacy (`QLT-AUT-*`, `QLT-PRV-001`, `GO-TSP-008`) | 5 | 0 | 1 | 1 real by design (telemetry), the rest false positives |
| Supply chain (`QLT-SUP-*`, `QLT-PRF-003`) | 46 | 0 | 0 | Real, and under-reported by the tool |
| Structure and maintainability (`QLT-CFT-*`, `GO-IDN-004`, `GO-TSP-005`, `QLT-PRF-005`) | 1444 | 800 | 83 | Real but low priority |

### 4.2 Security-relevant

**a) Response body not closed in the NetID provider (resource leak). Checked by hand. On master: yes.**

- `selfservice/strategy/oidc/provider_netid.go:135`: `Verify` posts the FedCM token to the NetID broker with `n.reg.HTTPClient(ctx).Do(req)` and decodes `res.Body`, but never closes the body and never checks the status code. The other 15 outbound provider requests in that package close their bodies.
- What it means: each FedCM login through NetID holds a connection until the garbage collector finalises the response, and an error response from the broker is decoded as if it were a token response.
- Fix: `defer res.Body.Close()`, check `res.StatusCode`, and read through an `io.LimitReader` as `provider_amazon.go:118` does.
- Of the 15 `GO-RRM-006` findings this is the only true positive. The others are functions that take an incoming `*http.Request` (`x/cookie.go:63`, `x/cookie.go:75`, `x/cookie.go:86`, `session/manager_http.go:138`, `courier/handler.go:142`), go-github calls that close their own bodies (`provider_github.go:65`, `provider_github_app.go:60`), and generated or test code.

**b) Integer conversions behind `//nolint:gosec // disable G115` that do truncate. Checked by hand. On master: yes.**

- `driver/config/config.go:349`: `var Argon2DefaultParallelism = uint8(runtime.NumCPU() * 2)`. On a host with 128 logical CPUs this is `uint8(256) == 0`; with 130 it is 4. `driver/config/config.go:543` applies the same `uint8` conversion to the configured `hashers.argon2.parallelism`, whose schema has `minimum: 1` and no maximum. `argon2.IDKey` panics when parallelism is 0 ("argon2: parallelism degree too low"), so on such hosts every Argon2 hash fails when Argon2 is the configured hasher, and other values are silently reduced.
- `courier/courier_dispatcher.go:104`: `NextMessages(ctx, uint8(pullCount))`. `courier.worker.pull_count` has no maximum in the schema, so 256 becomes 0 and 300 becomes 44.
- What it means: these are operator settings, not attacker input, but the suppression comment names the check without saying why the conversion is safe, and in these cases it is not.
- Fix: clamp to the target range (or add a `maximum` to the JSON schema) before converting, and state the bound in the suppression comment.

**c) Unjustified lint suppressions. 25 reported; all 18 in Kratos packages checked by hand.**

- 17 suppressions name a check but give no reason, for example `hash/hasher_argon2.go:45`, `selfservice/strategy/password/validator.go:178`, `selfservice/strategy/passkey/passkey_login.go:388` (`//nolint:staticcheck` with no check named) and `schema/handler.go:234` (`os.ReadFile(uri.Host + uri.Path) //nolint:gosec`, a file read from a configured schema URL, which is fine for operator configuration but should say so).
- False positive: `hash/hash_comparator.go:33`, where the justification ("compatibility for imported passwords") is on the following `//lint:ignore` line.
- Fix: one line of reason per suppression; writing them would also have surfaced item b.

**d) Courier worker ignores cancellation. Checked by hand. On master: yes.**

- `courier/courier.go:96` to `108`: `watchMessages` loops forever, retrying with `backoff.Retry` (no context) and sleeping with `time.Sleep(wait)`. `Work` (`courier/courier.go:75` to `90`) creates `errChan`, closes it with `defer` and returns as soon as the context ends, while the goroutine keeps running.
- What it means: after cancellation the goroutine keeps querying the database until the exponential backoff gives up (15 minutes by default in cenkalti/backoff v2.2.1) and then sends on the closed channel, which panics. In `kratos serve` the process is normally exiting by then, so the effect shows mainly in embedders, tests and graceful-shutdown paths.
- Fix: use `backoff.WithContext`, replace `time.Sleep` with a `select` on `ctx.Done()` and a timer, and return when the context ends.
- `GO-RRM-003` also flagged `oryx/metricsx/middleware.go:270` (the telemetry memory sampler loops with `time.Sleep` and no way to stop) and `oryx/resilience/retry.go:32`; we did not review those in depth.

**e) `http.DefaultClient` without a timeout. 10 findings (`GO-RRM-001`, `GO-IDN-005`); checked by hand.**

- False positive for the server: Kratos makes outbound calls through `RegistryDefault.HTTPClient` (`driver/registry_default.go:773`), which sets a 30 second timeout, two retries and the private IP range guard. The CLI sets a 10 second timeout (`cmd/cliclient/client.go:75`). `oryx/jwksx/fetcher.go:31` and `oryx/httpx/wait_for.go:19` are not called by Kratos.
- Real for SDK users: the generated Go client falls back to `http.DefaultClient` when the caller passes none (`pkg/client-go/client.go:69`, and the same in `pkg/httpclient/client.go:69`), so applications that use the SDK with defaults have no timeout. A default client with a timeout in the generator template would fix this.

**f) Context not propagated. 147 findings (`GO-RRM-002`, `GO-RRM-007`); sampled.**

- `GO-RRM-002`: 82 of 99 are in test helpers (`pkg/testhelpers`). The generated SDK findings are false positives: `prepareRequest` attaches the context with `WithContext` after `http.NewRequest` (`pkg/client-go/client.go:426`). The one in Kratos proper is `driver/registry_default.go:754`, `Ping()` with `context.Background()`, next to a `PingContext` that does the right thing; low impact.
- `GO-RRM-007` (48): false positives. The flagged files are interface definitions (`identity/pool.go`, `hash/hasher.go`, `x/transaction.go`) or methods whose signature an interface requires, such as `TableName(ctx)` in `selfservice/errorx/error.go:37`.

**g) Unbounded reads. 18 `QLT-CFT-010` findings in Kratos packages; 5 sampled.**

- Real, low: `identity/handler.go:1098` reads the admin `PATCH /admin/identities/{id}` body with `io.ReadAll(r.Body)` and no size limit. It is an admin endpoint, but an `http.MaxBytesReader` would bound memory per request.
- False positives: `courier/http_channel.go:126`, `schema/handler.go:259` and `schema/schema.go:143` read through an `io.LimitReader` applied earlier in the same function.

**h) Secret formatting, weak or test crypto. Checked by hand.**

- `GO-TSP-008` (`cipher/cipher.go:27`): not confirmed. The cipher secrets are `[32]byte` arrays and we found no path that formats them; we judged it not applicable.
- `QLT-AUT-004` (`selfservice/flow/continue_with.go:26`): false positive; it is the action name `set_ory_session_token`, not a credential.
- `QLT-AUT-007` (`pkg/testhelpers/e2e_server.go:147`, `InsecureSkipVerify`): test helper, not linked into the server binary (checked with `go list -deps`), so not a production issue.
- Weak algorithms by design: `hash/hash_comparator.go:12` to `35` import MD4, MD5 and SHA-1 to verify imported legacy password hashes. That is a documented feature and limited to comparison; no action needed beyond the suppression comments in item c.
- `cipher/aes.go:10` uses `github.com/gtank/cryptopasta` (last changed in 2017) for AES-GCM encryption of OIDC tokens at rest. The construction is sound (random nonce from `crypto/rand`), but it is an unmaintained dependency in a security path; inlining the few functions it provides would remove it.

**i) Telemetry. `QLT-PRV-001`, 2 findings; checked by hand.**

- Real, by design: `cmd/daemon/serve.go:229` to `309` sends anonymised usage reports to `https://sqa.ory.sh` unless `--sqa-opt-out` or `SQA_OPT_OUT` is set, and the sampler in `oryx/metricsx/middleware.go:246` also reports memory statistics. This is documented. For an identity service, opt-in, or at least a start-up log line saying that telemetry is on and how to turn it off, would help operators with data-protection obligations.
- False positive: `oryx/otelx/withspan.go:65` is a comment containing a vendor documentation URL.

**j) CI and release supply chain. Checked by hand; the framework under-reports this group.**

- Mutable action references: `.github/workflows` contains 54 action references and none is pinned to a commit SHA. Twelve follow a branch or `latest`, including `ory/ci/releaser@master` in the release job (`.github/workflows/ci.yaml:335`), which receives `ORY_BOT_PAT`, `GORELEASER_KEY`, `COSIGN_PWD` and the Docker Hub credentials; `aquasecurity/trivy-action@master` (`cve-scan.yaml:99`) and `kubescape/github-action@main` (`cve-scan.yaml:90`), which run in a job with `security-events: write` and a registry token; and `browser-actions/setup-chrome@latest` (`ci.yaml:125`). The framework reported 43, two of which are commented-out lines (`ci.yaml:127`, `ci.yaml:129`), and it missed 13, including all nine `ory/ci/*@master` references.
- Remote build inputs on a branch: `.goreleaser.yml:5` includes `build.tmpl.yml` from the `master` branch of `ory/xgoreleaser`, and `.goreleaser.yml:20` runs `bash <(curl -s .../master/docs.sh)` after the release. The template itself pins `cosign.key`, `cosign.pub` and `rename.sh` to a commit, which is the right pattern to extend to the include and the hook.
- Signing key: the template downloads an encrypted cosign private key from a public repository, so the strength of release signatures rests on `COSIGN_PWD` alone. Keyless signing with the workflow's OIDC identity, or a KMS-held key, would remove that dependency.
- The scan does not cover what ships: `cve-scan.yaml` builds the image with `make docker`, which uses `.docker/Dockerfile-build` (Debian builder, distroless runtime). The Alpine image that goreleaser publishes (`.docker/Dockerfile-alpine`) and the distroless static image are never scanned. The workflow has no `schedule`, so published tags are not rescanned when new advisories appear. Both points still hold on master.
- Scanner ignores without reasons: `.trivyignore` lists CVE-2022-30065, CVE-2024-2961 and CVE-2023-2650 with no comment, and `.grype.yaml` lists seven entries, most without a reason and some for glibc, which the Alpine image does not contain. A short reason and a review date per entry would keep these from outliving their cause; `.nancy-ignore` already does this well.
- SBOM: `QLT-SUP-010` is a false positive for binaries. The shared goreleaser template runs `cyclonedx-gomod` for every build; the framework could not follow the remote include. We did not find an SBOM or provenance attestation attached to the container images.
- Dependency audit: `QLT-SUP-007` is partly a false positive. Nancy runs in the `test` job, which the release job depends on, but it covers Go modules only, not the standard library or the base image, and it runs at build time only.

### 4.3 Maintainability

- **SDK shape rules, not applicable (1329 findings).** `GO-IDN-003` (public API in the root package), `GO-TSP-002` (unknown-field preservation) and most of `GO-IDN-001` (json tags) describe a generated client library. In Kratos packages the `GO-IDN-001` hits are the `Body` fields of swagger parameter wrappers, for example `identity/handler.go:873` and `selfservice/flow/login/handler.go:782`, which are not serialised as JSON. We judged the group a false positive for the server.
- **Complexity (`QLT-CFT-001` to `004`; 83 in Kratos packages).** The largest are `identity/manager.go:159` (`findExistingAuthMethod`, 28 branches), `driver/registry_default.go:586` (`Init`, 25 branches, 81 statements), `persistence/sql/identity/persister_identity.go:623` (`CreateIdentities`, nesting depth 8) and `identity/identity.go:475` (`WithDeclassifiedCredentials`, depth 7). The first and last decide which credentials are matched or revealed, so they are where splitting the function would most help review.
- **Duplication (`QLT-CFT-011`; 139 in Kratos packages).** For example the login, registration and recovery code persisters (`persistence/sql/persister_login_code.go:65`, `persister_registration_code.go:72`, `persister_recovery_code.go:80`) and the public and admin server set-up in `cmd/daemon/serve.go:98` and `:178`. `oryx/hasherx` repeats the Argon2 and PBKDF2 decoding in `hash/hash_comparator.go:434` to `478`; Kratos does not link `hasherx`, so the copy can drift unnoticed.
- **One logic slip found while reading: `selfservice/strategy/oidc/provider_github.go:102`.** `k == len(emails)` can never be true, so when GitHub returns no primary address the GitHub provider sets no email, whereas the GitHub App provider (`provider_github_app.go:89`) correctly uses `len(emails)-1`. Still present on master.
- **Deprecated APIs (`staticcheck` SA1019, 967 hits).** Almost all are tests calling the deprecated `config.Config.MustSet`; outside tests the notable ones are `ui/node.InputAttributes.OnClick` (9) and `strings.Title` (1).
- **Enum types (`GO-TSP-005`, 6).** `courier.MessageStatus`, `courier.MessageType` and `text.ID` are `int` types with hand-written JSON handling; we judged these not to be defects.
- The framework's own `go test ./...` leg timed out after 600 seconds; that is a limit of the tool run, not a test failure.

## 5. What Centipod did

### 5.1 Patched branch

Fork: `https://github.com/centipod/kratos`, branch `centipod/v26.2.0-security`, based on tag v26.2.0. No Kratos source file was changed; only `go.mod`, `go.sum`, `oryx/go.mod`, `oryx/go.sum` and the Dockerfiles.

| Commit | Change |
| --- | --- |
| `ed9df2c70` | `build: require the Go 1.26.11 toolchain` (`toolchain go1.26.11`; builder and debug images pinned to `golang:1.26.11-trixie`) |
| `bf45f8602` | `chore: run go mod tidy on the v26.2.0 module` (drops the unused `laher/mergefs` requirement, so the bumps stay clean) |
| `0f8c29a39` | `fix(deps): bump github.com/jackc/pgx/v5 to v5.10.0` |
| `88404a76c` | `fix(deps): bump go-jose v3 to v3.0.5 and v4 to v4.1.6` |
| `9667be9cb` | `fix(deps): bump golang.org/x/net to v0.62.0 and its x/ siblings` (x/crypto v0.58.0, x/text v0.43.0, x/mod v0.41.0 and others by minimum version selection) |
| `8d998a88b` | `fix(deps): bump OpenTelemetry Go to v1.44.0` (core, SDK and the stable exporters together) |
| `6779bdfe8` | `fix(deps): bump google.golang.org/grpc to v1.83.2` |
| `4aa3202c2` | `build: move the Alpine runtime image to 3.24.4` |

A copy of this report is committed on that branch as `CENTIPOD-ASSESSMENT.md`.

We kept Alpine rather than moving to distroless: the Alpine image is the one that carries the CGO and musl SQLite build and a shell, and Ory already publishes a separate distroless tag without SQLite.

### 5.2 Image build

The image was built the way goreleaser builds the `-amd64` Alpine tag: the binary with `CGO_ENABLED=1`, a musl C compiler (in `golang:1.26.11-alpine3.24`), tags `sqlite,hsm,json1` and `-s -w` with version, commit and date in `ldflags`; then `.docker/Dockerfile-alpine` from the branch, unchanged apart from the base image, for `linux/amd64`. Result: `centipod/kratos:v26.2.0-centipod.1`, image ID `sha256:9037b545db02458672480abec8afa71c1ae5b3fb1651129da8b8ec2004acdbb7`, 26.8 MB.

Smoke test from the image: `kratos version` reports `v26.2.0-centipod.1` and commit `4aa3202c2`; `kratos serve --help` prints the expected flags. Inside the image: Alpine 3.24.4, user `ory` (uid 10000), `/var/lib/sqlite` owned by `ory`, OpenSSL 3.5.9-r0, musl 1.2.6-r3, zlib 1.4-r0.

### 5.3 Verification

- `go build ./...`: passes on both branches.
- `go vet ./...` (whole root module): passes on both branches with no findings.
- `go test -tags sqlite -short -count=1` on `./selfservice/... ./identity/... ./session/... ./courier/... ./hash/... ./cipher/... ./x/... ./driver/... ./persistence/... ./schema/... ./continuity/... ./request/...`: 40 packages pass on the patched branch, 45 on the branch from master.
- Not run, because they start Ory Hydra in Docker through `dockertest`: in `selfservice/strategy/oidc`, `TestStrategy`, `TestSettingsStrategy` and `TestPostEndpointRedirect` (and `TestSettingsOrganizationFlow` on master); in `selfservice/strategy/password`, `TestOAuth2Provider` and `TestOAuth2ProviderRegistration`. With those excluded, both packages pass.
- Not run: the PostgreSQL, MySQL and CockroachDB persister tests (`-short` selects SQLite only). The pgx v5 bump is therefore compiled and type-checked but was not exercised against a live PostgreSQL here.
- Trivy on the rebuilt image: 0 CRITICAL, 4 HIGH, 6 MEDIUM, 4 LOW, 1 UNKNOWN (section 3).

### 5.4 Branch from master

Branch `centipod/upstream-security` in the same fork, based on master `b86338da0`, carries only what master still lacks: `go mod tidy` (`beeadd4e4`), the Go 1.26.11 toolchain (`bf87f124c`), go-jose/v4 v4.1.6 (`0e95964de`), golang.org/x/net v0.62.0 (`9fa390fe8`), grpc v1.83.2 (`d7c876717`) and Alpine 3.24.4 (`6cf05ebe1`). `trivy fs` on its server Go modules reports one HIGH (go-jose v3, CVE-2026-116587, no fix). It leaves `oryx/randx/strength/go.mod` alone: that separate tool module has x/image and x/text advisories but is not part of the server. We have not opened a pull request; you are welcome to take any of these commits.

## 6. Recommendations, ordered by value

1. **Release from master with the remaining bumps** (go-jose/v4 v4.1.6, x/net v0.62.0, grpc v1.83.2, Go 1.26.11, a current Alpine). This takes the published image from 4 CRITICAL and 72 HIGH to no fixable HIGH.
2. **Scan what you publish, on a schedule.** Point the CVE scan at the Alpine and distroless images that goreleaser builds, and add a scheduled run against the latest published tags, so new advisories against a release are noticed.
3. **Rebuild and re-release images regularly**, for example a monthly patch rebuild of supported tags, so base layer fixes reach users without waiting for a feature release.
4. **Pin the release pipeline**: actions by commit SHA (above all `ory/ci/releaser`, `trivy-action` and `kubescape`), and the goreleaser include and after hook by commit, as the template already does for the cosign files. Consider keyless or KMS-backed cosign signing.
5. **Pin the Go patch level** with a `toolchain` line, and let Dependabot or Renovate raise it.
6. **Keep test tooling out of the server binary**: move `oryx/dbal/testhelpers.go` (and the `dockertest` import it brings) into a test-only package, and move `oryx/jwksx` and `oryx/josex` to go-jose v4.
7. **Fix the confirmed defects**: close and check the NetID broker response (`provider_netid.go:135`); clamp Argon2 parallelism and the courier pull count before the `uint8` conversions (`config.go:349`, `config.go:543`, `courier_dispatcher.go:104`); make the courier loop context-aware (`courier.go:96` to `108`); bound the admin PATCH body (`identity/handler.go:1098`); correct `k == len(emails)` in `provider_github.go:102`.
8. **Give every scanner ignore and lint suppression a reason**, and give scanner ignores a review date.
9. **Give the generated Go SDK a default client with a timeout**, so SDK users do not inherit `http.DefaultClient`.
10. **Consider making usage telemetry opt-in**, or at least announcing it at start-up, for an identity service.

Thank you for maintaining Kratos. We are happy to answer questions about any item here or to share the raw scanner output.
