# Shared security threat model

## Scope and evidence

Repositories: `reta-ygs/dotfiles`, `reta-ygs/kysc`, `reta-ygs/kysc-kb`, `secureta/vulnlake`, and `reta-ygs/www` on GitHub. This model covers the whole of each repository.

This is a shared prioritization model, not a vulnerability report or a live-deployment assessment. Repository paths below are relative to their named repository. It consolidates existing security-boundary documentation from `kysc-kb/CLAUDE.md` ("セキュリティ境界"), `kysc-kb/README.md` (access model), `dotfiles/AGENTS.md`, and `vulnlake/AGENTS.md` (publication invariants). Each repository keeps a copy at its root; architecture changes should update the affected sections across these copies.

Evidence labels:
- **Requester-confirmed:** the five repository selections, security objective, and a shared threat model used for reranking.
- **Repository-documented:** the maintainer-authored requirements cited explicitly below. These are intended boundaries, not proof of deployed enforcement.
- **Code-derived:** architecture and controls inferred from the current checkout. These do not independently justify changing scanner severity.
- **Unconfirmed:** deployment details, asset priorities, attacker exclusions, and accepted risks awaiting requester input. Silence is not risk acceptance.

## System overview and components

These repositories form several related systems, not a single web application. `dotfiles` also carries deployment integration for `kysc-kb`; there is no verified runtime connection between the public sites and the private KB or dataset publisher.

| Stable component   | Code covered                                                                                                                       | Trust boundary and role                                                                                                                                                                                                                     |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Developer Hosts    | dotfiles: `flake.nix`, `nix/home.nix`, `nix/nixos/`, other host modules, `nix/pkgs/`                                               | Operator workstations, Incus/NixOS containers, Lima VM, terminal bridges, SSH and remote agent services. Separates local users, service identities, containers, remote clients and host privileges.                                         |
| Automation         | dotfiles: `nix/files/`, `scripts/`, automation-specific Nix modules; all repositories: `.github/`, dependency-update configuration | Scheduled/agent-driven maintenance and CI consume repository changes and upstream releases, sometimes with publication or repository credentials. Tests are evidence, not deployed controls.                                                |
| KYSC Website       | kysc: `src/`, `public/`, `astro.config.mjs`                                                                                        | Public organizational site, built as static Astro output for Cloudflare Pages. Uploaded PDFs and pages are public read surfaces; authoring and deployment remain privileged.                                                                |
| Personal Website   | www: `src/`, `public/`, `astro.config.mjs`, `scripts/`                                                                             | Static Astro/React blog, tags and RSS/Atom feeds. Browsers consume build output; Markdown/MDX and dependencies cross the build-time code boundary.                                                                                          |
| KB Ingestion       | kysc-kb: `kb_pipeline/`, `nix/module.nix`, `nix/officers.nix`, `nix/secretariat.nix`, related flake and deployment wiring          | OneDrive originals enter conversion/OCR and a headless coding-agent Wiki generator. Synchronization, generation, and audience-specific stores have different identities and permissions.                                                    |
| KB Access          | kysc-kb: `open_webui/`, `kb_originals/`, `nix/ui.nix`, `nix/originals.nix`, `nix/webui-originals.nix`                              | Cloudflare Tunnel/Open WebUI authentication, model/audience authorization, Hermes routing, encrypted conversation metadata and private original-document downloads.                                                                         |
| KB Query Agents    | kysc-kb: `scripts/deploy.sh`, `scripts/update-containers.py`, agent settings under `nix/`                                          | Private agents search read-only, audience-specific Wiki mounts and call external model providers. The original-document inbox is not mounted by query agents.                                                                               |
| Dataset Publishing | vulnlake: `src/vlake/`, publication configuration                                                                                  | CLI/CI retrieves third-party vulnerability datasets, converts them to Parquet, updates DuckLake metadata, and publishes catalog/data through S3-compatible storage and public HTTPS. No application request-handling server was identified. |

For shared Nix files, classify by the actual subsystem affected. CI/workflow findings use Automation; publisher implementation findings use Dataset Publishing.

## Entry points and data flows

1. **Public browsers → websites.** `www.kysc.or.jp` and `www.reta.dev` serve static pages, assets, links and feeds. No application login, database, or server-side API was identified in these site repositories. Cloudflare account policy and live deployment settings are outside the visible code.
2. **Remote clients → Developer Hosts.** SSH, remote terminal/agent services, and Cloudflare-published Ovis reach powerful developer sessions. `dotfiles/nix/nixos/ovis.nix` configures loopback origin binding and Cloudflare Access settings. `herdr-ssh.nix` configures a public-key-only forced command with source restriction and forwarding disabled. The Ovis application source is a pinned external repository, not one of the five scan targets.
3. **OneDrive collaborators → KB Ingestion.** Explicit source folders are synchronized by rclone; originals pass through parsers/OCR and coding-agent generation; some Wiki outputs synchronize back to an explicitly configured OneDrive path. Originals and model-generated output are untrusted, even when supplied by an otherwise authorized collaborator.
4. **Users → Cloudflare → Open WebUI.** `nix/ui.nix` binds Open WebUI to loopback and configures a trusted Cloudflare email header. The actual edge Access policy is not in this checkout.
   - **Wiki queries:** `open_webui/hermes_router.py` checks model access, routes queries to the audience-specific agents, and encrypts history metadata with Fernet. The agents search the Wiki.
   - **Original downloads:** `kb_originals/webui.py` checks user and model access before proxying downloads to the private originals service (`kb_originals/server.py`), not to query agents.
5. **Upstream datasets → publisher → public catalog consumers.** `src/vlake/{epss,cvelist,ghsa,exploitdb,nuclei,cwe,kev,cloudflare_waf,mitre}.py` parse external source data. `pipeline.py`, `lake.py`, `storage.py`, and `config.py` govern publication and local/S3 destinations. Public consumers query DuckLake over HTTPS; this is not public write authorization.
6. **Contributors/dependencies → automation → privileged outputs.** GitHub workflows, Nix inputs, package registries, generated code, and agent tooling cross into build/deploy environments. A malicious dependency or upstream document is distinct from a fully compromised maintainer account; do not conflate their access.

## Assets and sensitivity

The following are code-derived protection candidates, not requester-confirmed special severity multipliers:

- OneDrive owner-account credentials: repository documentation says the token can read the personal drive beyond configured synchronization paths.
- Private common/secretariat/officers originals, generated Wiki content, prompts, chat histories and audience memberships. Exact classifications and real document contents are unknown.
- Cloudflare, GitHub, S3, SSH, model-provider/OAuth and developer-tool credentials; host sessions, working copies, signing identity and administrative access.
- Integrity, consistency and availability of organizational pages, personal articles/feeds, and public vulnerability datasets consumed by others.
- Wiki/state manifests and revision history needed for recovery; published catalog/data consistency; inference usage and operational continuity.

## Attacker model

Provisional coverage includes unauthenticated outsiders; low-privilege authenticated KB users; contributors or collaborators who can supply documents/data without administrative access; malicious upstream data, packages or updates; and compromised service identities attempting lateral movement. Host administrators and repository maintainers are powerful trust principals, but no explicit requester exclusion has yet been given for compromise involving them.

Treat attacker access and exploit preconditions as the scanner verifies them. Never treat Internet access as equivalent to authenticated UI access, OneDrive write access, CI secret access, or host root.

## Existing controls and maintainer requirements

### Repository-documented boundaries

- **KB credential separation:** `kysc-kb/README.md` documents owner-token plus explicit-path synchronization as an adopted design, not credential-scoped delegation. `CLAUDE.md` requires rclone configuration isolation from the LLM-running build identity, private homes/credential modes, and no secrets in the Nix store. Broad owner-token scope is documented; this is not blanket acceptance of token leakage or arbitrary synchronization.
- **KB agent containment:** `kysc-kb/CLAUDE.md` requires systemd hardening and narrowly writable Wiki/state/build-home paths, with inbox originals read-only. It explicitly assumes malicious-document prompt injection. The build agent's own OAuth identity remains a distinct exposure from the rclone identity; do not claim all model credentials are inaccessible to the build process.
- **KB audience separation:** `kysc-kb/README.md` documents a shared officers/secretariat group, currently separate search agents, model-authorized original downloads, and disabled chat sharing. The officers Wiki is not synchronized back to OneDrive. These are required intended boundaries, not permission to expose data outside authorized audiences.
- **Remote developer access:** `dotfiles/AGENTS.md` requires Ovis loopback binding and origin-side Cloudflare Access RS256 JWT verification for the configured single identity, prohibits anonymous/all-tailnet access, and requires private credential handling. It explicitly says agent review/search restrictions are not OS isolation.
- **Dataset publication:** `vulnlake/README.md` intentionally offers anonymous public catalog reads. `AGENTS.md` requires data-file upload before catalog replacement, shared publication concurrency, SHA-pinned Actions and non-persistent checkout credentials. It describes ExploitDB/nuclei redistribution as metadata/link references, not execution of exploit/template code.

### Code-derived controls, not live attestations

- KB UI loopback binding, disabled direct firewall opening, explicit private original-server addresses and source-IP firewall rules are expressed in Nix. UI authorization and original-download checks exist in Python.
- KB conversation-history Fernet handling and repeated model-access checks are present in the Hermes router. Key distribution, rotation and deployed settings are unverified.
- KYSC has a restrictive static response-header policy in `public/_headers`; the personal site's `astro.config.mjs` enables Astro CSP. These statements do not prove edge/header enforcement.
- Nix/package lockfiles, dependency policies and CI tests exist. `vulnlake/.github/workflows/publish.yml` declares read-only repository permissions, a publication environment, publication concurrency, and S3 credentials supplied from environment secrets; actual secret scopes and environment protection remain unknown.

## Accepted risk and out of scope

No additional requester-approved risk acceptance or attacker exclusion has been supplied.

Intentional public website/catalog reads are repository-documented behavior, not confidentiality defects on their own. Unauthorized modification, secret exposure, private document disclosure, or malicious code execution are not accepted merely because outputs are public.

Coverage is repository-based. Live cloud policies, OneDrive sharing ACLs, object-store IAM/public-write settings, deployed image state and upstream application internals are not fully represented. Their absence is an evidence limitation, not acceptance of risk. This document does not itself authorize active probing of public services, remediation, or code changes.

## Open questions

- Which attacker classes, if any, does the requester explicitly exclude?
- Which assets are especially critical beyond the ordinary impact already captured by scanner severity?
- Are there additional accepted risks, and which finding labels besides Component are useful?
- Do deployed Cloudflare policies, original-server network restrictions, OneDrive sharing and S3 permissions match the intended configuration? No additional infrastructure repository is necessary to begin: infrastructure code is present in dotfiles and kysc-kb, and CI publication configuration is present in vulnlake. External control-plane policy remains unverified.

## Prioritization policy

Start with the scanner's severity and its verified access/exploit preconditions. Move a priority only for an explicit requester fact or a clearly applicable maintainer-documented security-model fact, generally downward for genuinely excluded attackers/surfaces or accepted risks. Code-derived architecture and unanswered assumptions do not justify moving a finding. Raise only rarely for a requester-designated critical asset reached through the scanner-confirmed path; never raise hard-to-exploit or unverified findings. No severity is changed simply because a component contains credentials or private data.

Finding labels initially use **Component**, with values exactly matching the component table. Additional requested label kinds can be added without changing scanner scope.
