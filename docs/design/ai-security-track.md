# AI Security Track

## Purpose

R6 establishes a vendor-neutral security layer for model clients and agents. Its goal is to detect and inspect prompt injection, sensitive-data leakage and agent abuse while using Wazuh as the correlation and alerting layer.

R6 begins alert-only. Identity action and automated remediation remain out of scope until R7.

## Scope and Architecture

All local and cloud model traffic must pass through an inline gateway container. Clients and agents must not receive direct access to model endpoints.

The gateway applies route-specific policy, records privacy-preserving security events and forwards those events over an authenticated channel to storage that the gateway cannot modify. A versioned adapter translates the vendor-neutral event contract for Wazuh.

Detection proceeds from least expensive to most expensive:

1. Pattern rules
2. A small classifier in the Prompt Guard 2 class
3. Output checks for secrets, personally identifiable information and canary tokens
4. Agent tool-call policy, including allowlists, argument validation and egress limits

Each route has an explicit operating mode and threshold. Initial deployment is monitor-only. R6 does not contain response nodes or identity actions.

## Revision Controls

### Alert-Only Start

R6 ships alert-only. It can classify, correlate, notify and recommend action, but it cannot disable a key, disable an account, quarantine a route or execute another response.

Identity and remediation actions begin only in R7 after separate review and approval controls are present.

### Response Limits

Later automated response is limited to reversible quarantine of one route or one disposable credential. Every action requires:

- Human approval
- Validated event provenance
- Rate limits
- Cooldowns
- A tested out-of-band break-glass identity
- Separately documented and tested provider-specific revocation and recovery procedures

Wazuh Active Response must never hold or act through the operator's own identity.

### Gateway Enforcement

Gateway use is enforced technically:

- Model ports are not published.
- Gateway, clients and model services use separate container networks.
- Host and container egress default to deny.
- Model destinations use an allowlist on a firewall the gateway cannot administer.
- DNS controls restrict resolution and destination changes.
- Redirect-based bypasses are blocked.
- Unapproved proxy environment variables are blocked.
- Model sockets are not mounted into agent containers.
- Scheduled bypass tests must fail closed.

The policy administration identity is separate from the runtime identity. Credentials are scoped per route.

### Logging Contract

Security logging defaults to denial of content capture.

The SIEM must never store:

- Raw prompts
- Raw outputs
- Authorization headers
- Tool arguments
- Retrieved content

Permitted fields are:

| Field class | Examples |
|---|---|
| Integrity references | Request and response hashes |
| Classification | Injection, leakage or policy classification |
| Routing | Opaque route identifier |
| Measurements | Request size, response size and bounded duration |
| Decisions | Monitor, allow, deny or fail-state decision |
| Context | Bounded, sanitized excerpts that pass redaction tests |

Body logging is disabled in proxies, exception handlers and crash handlers. Redaction is tested in CI with seeded synthetic secrets. The log index is encrypted, uses shorter retention than ordinary security indices and is limited by role.

Deletion verification includes snapshots.

### Resilience

Every route records whether it fails closed or qualifies for the narrowly defined fail-open exception.

The gateway provides:

- Request-size limits
- Request and connection time bounds
- Health checks
- A circuit breaker
- Resource limits
- Queue-depth and dropped-event metrics
- A tested rollback
- Route-scoped credentials
- A disabled-by-default local recovery route

Audit events travel through an authenticated channel to storage that the gateway cannot alter.

### Vendor-Neutral Pre-GA Work

Before Wazuh 5.0 general availability, R6 may build only vendor-neutral assets:

- Event schemas
- Threat cases
- Detection fixtures
- Gateway policies
- Redaction tests
- Transport adapters

Wazuh integration remains behind a versioned adapter. No 4.x custom decoders or index mappings are added unless a time-boxed 4.x deployment requires them.

This limit addresses the risk that Wazuh 5.0 schema enforcement could reject custom fields.

### Validation Isolation

garak and PyRIT run only against an isolated validation route with:

- Synthetic data
- Non-production credentials
- Spend caps
- Request caps
- A maintenance window
- Active Response disabled
- Validation events labeled separately from incidents

Detection fixtures are replayed in CI. Validation results track false positives and known detection limits.

Validation tooling must not target production routes or use production data.

### One-Operator Controls

The design accounts for a single operator and approximately seven available hours per week.

Required controls include:

- Documented service-level objectives
- A dead-man alert whose delivery path does not depend on the SIEM
- Certificate and key expiry alerts
- Queue-depth and dropped-event metrics
- Weekly exception review
- Bounded paging
- Operator runbooks
- Quarterly recovery exercises

Alert volume must fit the available operating capacity. Repeated low-value alerts must be tuned, grouped or downgraded.

### Advisory Endpoint Hooks

Coding-agent hooks provide advisory telemetry only. Hook events include tool use, file-access metadata, egress metadata, agent configuration and agent version.

Hook telemetry is correlated with independent audit or eBPF data. Heartbeat and hook-policy drift alerts detect missing or altered coverage.

A hook event alone is not sufficient evidence for an automated response.

### Coverage Labels

Every mapping to OWASP LLM Top 10 2026, an agentic-security taxonomy or MITRE ATLAS carries one of these labels:

| Label | Meaning |
|---|---|
| Mapped | A documented relationship exists. |
| Implemented | A corresponding control or detection exists. |
| Tested | A passing fixture exercises the implementation. |
| Effective | Operational evidence demonstrates the intended result within stated limits. |

Taxonomy versions are pinned by date. Every claimed item includes a passing fixture and known limitations. A mapping must not be presented as tested or effective merely because a rule exists.

### Recovery Route

The manual recovery route is:

- Disabled by default
- Activated only from the local console
- Limited to local destinations
- Time-bounded with automatic expiry
- Protected by strong operator authentication
- Independent of the gateway identity and policy plane
- Offline-capable
- Single-use or short-lived
- Limited to one concurrent activation

Activation creates an immutable audit record and an independent alert. The route is included in scheduled bypass tests, quarterly expiry tests and quarterly outage drills.

The recovery route never provides cloud access.

### Fail-Open Rules

Fail-open is allowed only when a route is all of the following:

- Explicitly classified as low risk
- Local-only
- Restricted to synthetic or non-sensitive data
- Free of credentials
- Free of tools
- Restricted by a local-destination allowlist

These requirements are enforced technically. Configuration drift detection automatically reclassifies the route to fail-closed if any requirement is violated.

Every agentic, cloud, credential-bearing or data-bearing route fails closed. Each fail-state decision is documented, tested and paired with compensating telemetry.

### Cryptographic Erasure

Log-index data uses dedicated encryption keys assigned per index generation or retention epoch.

Every key copy is inventoried. The design defines the destruction order, required evidence and responsible role. Expired data is removed through short snapshot retention followed by key destruction, preserving snapshot immutability while providing cryptographic erasure.

Tests must prove both outcomes:

- Expired snapshots are unreadable after the applicable keys are destroyed.
- Retained snapshots remain restorable with their retained keys.

## Event and Correlation Flow

| Stage | Responsibility |
|---|---|
| Client or agent | Sends a request only through an approved gateway route. |
| Gateway | Enforces routing, size, time, content and tool policy. |
| Detection pipeline | Applies pattern, classifier, leakage and agent-policy checks. |
| Audit transport | Sends authenticated, privacy-preserving events to immutable-from-gateway storage. |
| Versioned adapter | Converts the vendor-neutral event into the supported Wazuh representation. |
| Wazuh | Correlates gateway, endpoint, audit and network events and raises alerts. |
| Operator | Reviews provenance and decides whether later R7 remediation is appropriate. |

## Threat Model

| Asset | Actor | Boundary | Abuse case | Mitigation | Verification |
|---|---|---|---|---|---|
| Model request data | External content author | Retrieved content to agent context | Untrusted content attempts to change the agent's intended behavior. | Gateway classification, content policy, tool restrictions and independent endpoint telemetry | Synthetic indirect-injection fixtures and isolated validation runs |
| Model response data | Model or compromised upstream service | Model endpoint to client | A response contains sensitive data or disallowed instructions. | Output scanning, canary detection, redaction and route policy | Seeded-secret CI tests and bounded false-negative review |
| Credentials | Malicious prompt, compromised agent or insider | Agent runtime to model or tool service | A request or tool call attempts to disclose or misuse a credential. | No credential logging, route-scoped credentials, tool allowlists, argument validation and egress restrictions | Seeded canary tests, credential-scope review and egress-denial tests |
| Tool authority | Compromised or manipulated agent | Agent to tool endpoint | An agent requests an action outside its approved purpose. | Tool allowlists, validated arguments, no tools on fail-open routes and alert-only R6 | Policy fixtures and correlated audit or eBPF evidence |
| Gateway policy | Compromised runtime identity | Runtime to policy administration plane | The gateway attempts to weaken its own restrictions. | Separate administration identity and firewall controls the gateway cannot administer | Privilege review and configuration-drift tests |
| Gateway availability | Resource exhaustion or upstream failure | Client to gateway | Excessive demand or dependency failure prevents model access. | Resource limits, time bounds, circuit breaker, queue metrics and route-specific fail behavior | Load tests, outage drills and dead-man alert tests |
| Gateway routing | Compromised client or agent | Client network to model network | Traffic attempts to avoid the gateway. | Unpublished model ports, separate networks, default-deny egress, DNS controls and destination allowlists | Scheduled bypass tests that must fail closed |
| Audit events | Compromised gateway | Gateway to audit storage | The gateway attempts to suppress or modify evidence. | Authenticated transport and storage the gateway cannot modify | Dropped-event metrics, sequence validation and immutable-storage checks |
| SIEM log data | Operator error, insider or compromised service | Gateway event store to Wazuh | Sensitive request content is retained or exposed. | Default-deny capture, bounded fields, redaction, role limits, encryption and short retention | Seeded-secret CI tests, access review and snapshot deletion tests |
| Detection classifier | Adversarial input | Request content to classifier | Input avoids or confuses detection. | Layered detection, tunable thresholds, correlation and known-limit documentation | garak and PyRIT on the isolated route plus fixture regression tests |
| Coding-agent telemetry | Compromised or altered hook | Agent hook to Wazuh | A hook omits, alters or fabricates activity. | Advisory-only treatment, heartbeat, policy-drift alerts and independent audit or eBPF correlation | Hook interruption tests and cross-source correlation tests |
| Recovery route | Unauthorized local user | Local console to recovery path | Recovery access is enabled without legitimate need. | Independent strong authentication, automatic expiry, immutable activation audit and concurrency limit | Quarterly activation, expiry and outage drills |
| Fail-open route | Misconfiguration or scope drift | Low-risk route to local model | A low-risk route gains credentials, tools or sensitive data while retaining fail-open behavior. | Technical eligibility checks, local allowlist, drift detection and automatic fail-closed reclassification | Configuration mutation fixtures and fail-state tests |
| Snapshot data | Reader of retained storage | Encrypted index to snapshot storage | Expired sensitive logs remain readable in old snapshots. | Per-generation or retention-epoch keys, key inventory and cryptographic erasure | Prove expired snapshots fail to decrypt while retained snapshots restore |
| Wazuh integration | Version or schema change | Vendor-neutral adapter to Wazuh | A schema change drops or rejects security events. | Versioned adapter, vendor-neutral fixtures and pre-GA integration limits | Adapter contract tests against each supported Wazuh version |
| Operator identity | Faulty response logic or compromised automation | Wazuh response to identity provider | Automation disables the only operator identity. | R6 alert-only, operator identity excluded from Active Response and tested out-of-band recovery | Response-policy tests in R7 before any response capability is enabled |

## Privacy and Retention

Prompts, outputs, retrieved content and tool arguments are treated as sensitive even when no secret has been identified.

| Control | Requirement |
|---|---|
| Collection | Capture only fields permitted by the logging contract. |
| Redaction | Redact before events leave the gateway. |
| Access | Restrict by operational role. |
| Retention | Keep AI security events for less time than ordinary security indices. |
| Encryption | Encrypt indices with dedicated generation or retention-epoch keys. |
| Snapshots | Apply short retention without weakening snapshot immutability. |
| Deletion | Verify cryptographic erasure across primary storage and expired snapshots. |

## Open Risks

| Risk | Current treatment | Remaining concern |
|---|---|---|
| Indirect injection in retrieved content | Layered gateway detection, tool restrictions and isolated validation | Novel content may evade classifiers and patterns. |
| Classifier evasion | Multiple detection tiers, correlation and regression fixtures | No classifier is complete, and effectiveness can drift. |
| Gateway bypass | Network separation, default-deny egress, DNS controls and scheduled bypass tests | Host-level misconfiguration could create an unintended path. |
| Latency | Cheapest-first detection, route-specific policy and resource limits | Additional checks may make interactive use slower. |
| Log volume | Bounded metadata, shorter retention and queue metrics | High request volume may still increase storage and review load. |
| Wazuh 5.0 schema enforcement | Vendor-neutral schema and versioned adapter | General-availability behavior may differ from release-candidate documentation. |
| Single-operator availability | Dead-man alerts, bounded paging, runbooks and recovery drills | Extended operator absence remains an operational constraint. |
| Recovery control misuse | Independent authentication, immutable audit, expiry and concurrency limits | Physical or local-console compromise could still affect recovery. |
| Cryptographic erasure execution | Per-epoch keys, full key inventory and tested destruction procedure | An untracked key copy would defeat erasure. |
| Validation safety | Isolated route, synthetic data, non-production credentials and request caps | Validation tools may generate unexpected load or findings. |
| Taxonomy drift | Dated mappings and explicit coverage labels | New taxonomy versions may invalidate prior coverage statements. |

No accepted residual risk from the final review is above Low. Operational evidence is still required before any control may be labeled effective.

## Commercial Reference Claims

The commercial reference product was CrowdStrike Falcon AIDR and Guardian. Product material claims capabilities including agent, MCP server and tool discovery; coding-agent hooks; prompt-injection detection; sensitive-data policy; an AI gateway with a kill switch; and an agent graph.

These are vendor claims and are unverified. They are reference inputs only, not evidence that this design or any commercial product provides those capabilities effectively.

## Review Record

| Review | Result |
|---|---|
| Review tier | Daybreak cyber-program tier |
| Rounds | Three |
| Round 1 | No Critical findings; five High findings |
| Round 2 | One High finding |
| Round 3 | No Critical or High findings |
| Final residuals | None accepted above Low |
