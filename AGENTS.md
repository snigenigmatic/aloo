# AGENTS.md

Guidance for AI coding agents working in this repository. Read this before making changes.

## What this is

`aloo` is an agent-facing safety layer for npm/npx packages. An AI coding agent (or a human) asks aloo to vet a package version before installing or executing it, and gets back a structured, explainable verdict: `allow`, `warn`, or `block`, with the exact reasons and evidence.

The detection engine is the product. Quality of detection is the thing that matters, measured against a labeled corpus. Distribution surfaces (CLI, MCP server) are thin shells over the engine.

Three rules govern every change here:

1. The engine is deterministic. Same input, same verdict. No exceptions.
2. The engine is pure and static. It reads bytes and reports. It never executes package code and never makes network calls.
3. Every change to detection is proven against the benchmark before it ships. Numbers, not claims.

## Project workflow

Treat GitHub issues as feature units and milestones as the delivery plan. Work should start from the issue, use a dedicated branch for that issue, and close through a pull request with validation results attached. Do not bundle unrelated issues in one branch.

CI is part of the product. It must build, test, lint, format-check, run the benchmark gate, and include supply-chain safety checks for Rust crates and generated release artifacts. A change is not ready if CI cannot prove the crate and packages are safe to consume.

## Commands

```
cargo build                          build the whole workspace
cargo test                           run all tests
cargo run -p aloo-bench            score the engine against the labeled corpus
cargo run -p aloo -- vet <path>    vet a package directory or .tgz tarball
cargo run -p aloo-mcp              start the MCP server over stdio
cargo clippy --all-targets           lint
cargo fmt                            format
```

The oxc-backed semantic analyzer is feature-gated and currently a stub:

```
cargo build -p aloo-engine --features oxc
```

Do not enable `oxc` in default builds. It is the planned upgrade path for the taint analysis, not the current backend.

## Workspace layout

| Crate | Path | Role |
| --- | --- | --- |
| `aloo-engine` | `crates/engine` | The detection engine. Pure, deterministic, no I/O beyond reading the package it is handed. |
| `aloo-bench` | `crates/bench` | Scores the engine against `crates/bench/corpus`. Prints precision, recall, false-positive rate. The quality gate. |
| `aloo-mcp` | `crates/mcp` | MCP server exposing the engine as a tool an agent calls before install/exec. |
| `aloo` (cli) | `crates/cli` | CLI shim. Exit code encodes the decision: 0 allow, 1 warn, 2 block. |
| `aloo-intelligence` | `crates/intelligence` | Background batch worker. Reads deterministic verdicts, generates `EnrichedVerdict`. Never in the realtime path. |

## Architecture

The engine has one boundary that must stay clean: the `Analyzer` trait.

```
PackageVersion ──> Analyzer ──> PackageFacts ──> signals ──> Vec<Reason> ──> score ──> Verdict
```

- `Analyzer` (`engine/src/analyzer.rs`) turns a package into `PackageFacts`: observed sources, sinks, and flows. This is the only component that understands JavaScript.
- The default backend is `HeuristicAnalyzer` (`engine/src/backend/heuristic.rs`): regex and line-level detection, co-occurrence reachability.
- The future backend is `OxcAnalyzer` (`engine/src/backend/oxc.rs`, feature `oxc`): real AST, scope resolution, and dataflow taint over oxc's semantic model.

The reason this boundary exists: the heuristic backend is good enough for v0, and oxc is a heavy dependency and a large build. We ship on heuristics now and swap in oxc behind the same trait later. That swap stays a swap only if you obey this:

**Never let oxc-specific types cross into the engine's public interface or into the signal passes.** Signals consume `PackageFacts` and nothing else. If a signal reaches into a backend or imports anything oxc, the boundary is broken and the future swap becomes a rewrite. This is the single most expensive mistake you can make in this codebase.

## How detection works

The domain model (`engine/src/model.rs`):

- A **source** is where sensitive data originates: `process.env`, `.env` files, npm tokens, SSH keys, AWS credentials, wallet data, browser data.
- A **sink** is where data escapes or code executes: network send, process exec, dynamic eval, filesystem write.
- A **flow** is a source reaching a sink. A flow from a credential source to a network sink is exfiltration. This is the core signal and the thing generic scanners miss.

Signal passes (`engine/src/signals/`), each returning `Vec<Reason>`:

- `manifest` — install/preinstall/postinstall scripts, and dangerous commands inside them.
- `entropy` — base64 blobs, fromCharCode chains, high-entropy literals.
- `ioc` — deterministic high-confidence indicators (exfil endpoints, eval-of-decoded-payload).
- `taint` — flows from `PackageFacts`. Credential source to network sink.
- `diff` — compares a version against its predecessor. A flow or install script that appears in a new release of a previously clean package is the account-takeover case, where reputation and age signals all say safe. Catching this is the wedge.

Scoring (`engine/src/score.rs`) is deterministic: any `Critical` reason blocks; otherwise severity weights accumulate against `warn` and `block` thresholds. Do not make scoring depend on anything outside the reasons list.

## Adding a new signal

1. Create `crates/engine/src/signals/<name>.rs` with `pub fn run(...) -> Vec<Reason>`. Take `&PackageVersion` and/or `&PackageFacts`, never a backend.
2. Declare it in `crates/engine/src/signals/mod.rs`.
3. Call it in `Engine::evaluate_against` in `crates/engine/src/lib.rs`.
4. Add at least one labeled fixture to `crates/bench/corpus/` that the signal is meant to catch, and one benign fixture that it must not flag.
5. Run `cargo run -p aloo-bench`. Confirm recall improved and the false-positive rate did not.

Every `Reason` must carry `evidence` (file, line, snippet). A verdict an agent cannot inspect is not acceptable. No evidence, no reason.

## The quality gate

`aloo-bench` is the gate. It loads `corpus/benign` and `corpus/malicious`, runs the engine, and reports the confusion matrix plus precision, recall, and false-positive rate.

A change to detection is not done until the bench shows it helped and did not regress. A heuristic that raises recall by flooding false positives is a regression. Treat the false-positive rate as the metric that decides whether anyone keeps aloo installed, because it is.

Fixtures are synthetic and inert. Use `example.com`, `localhost`, or `127.0.0.1` as endpoints. Representative attack patterns only. Never commit working exploit payloads, real command-and-control or exfiltration URLs, or copied live malware.

## Intelligence layer

aloo has two tiers. The deterministic engine detects. The intelligence layer explains. They are different jobs, run in different processes, and must never be confused.

```
realtime:  PackageVersion -> engine -> Verdict          (milliseconds, gates agents)
batch:     Verdict -> queue -> intelligence worker -> Enrichment   (seconds, for humans)
```

The intelligence layer is a background batch job. It reads the deterministic verdict and generates a narrative analysis, a false-positive assessment, campaign correlation, and a remediation recommendation. It writes an `EnrichedVerdict` to the store. It never touches the install path.

**The one hard rule: the intelligence layer must not change the verdict decision.** `decision` in the original `Verdict` is immutable after it is issued. The model may assess false-positive likelihood in the `false_positive` field, but it may not upgrade a Warn to a Block, downgrade a Block to an Allow, or in any other way modify the `verdict` object it received. The `EnrichedVerdict` carries the original `Verdict` byte-for-byte alongside the `Enrichment`. If you find yourself writing code that reads `enrichment` to make a security decision, that is an architecture violation.

**The model receives structured input only.** The prompt contains the package name, version, decision, score, and the `reasons` array with evidence snippets. It does not receive raw source files. The model is not doing detection. It is reading a finding and generating analysis. Do not blur this boundary.

**The intelligence layer lives in `aloo-intelligence`.** It imports `Verdict` and `EnrichedVerdict` from `aloo-engine` for types only. It never imports signals, the `Analyzer` trait, or scoring logic. It is the one crate where async and HTTP are correct, because the work is waiting on a model API.

**The intelligence layer is never in the critical path.** An agent or shell gate acts on `decision` from the synchronous `Verdict`. Enrichment is for the human reviewing decisions after the fact. Blocking an install on enrichment status is wrong.

**Model output is validated before storage.** If the model returns malformed JSON, a wrong shape, or a modified `decision`, the worker writes `EnrichmentStatus::Failed` and logs the raw response. It never panics and never stores a partial or invalid enrichment.

## Conventions

- No comments in code. Names and types carry the meaning. If something needs explanation, the design is wrong or it belongs in this file.
- Determinism is enforced, not aspirational. In the engine crate: no `SystemTime`, no randomness, no network, no environment-dependent behavior. Use `BTreeMap` over `HashMap` anywhere iteration order reaches output. Sort evidence before emitting.
- No LLM calls anywhere in the engine or in any signal pass. The intelligence layer is a separate crate, runs in a separate process, and is downstream of a fully committed verdict.
- Dependency discipline. The engine stays light. Do not add a crate without a reason that survives the question "can std or a few lines do this." Heavy analysis dependencies belong behind a feature flag, as oxc is.

## Safety and scope

- The engine and CLI never run package code. They statically analyze bytes. Any dynamic or sandboxed analysis is a separate future tier that must run inside an isolated sandbox (gVisor or Firecracker), never inside this crate and never on the host.
- The verdict JSON is a contract that agents depend on. `decision` is one of `allow`, `warn`, `block`. Each reason has `code`, `severity`, `title`, `detail`, `evidence`. Do not rename fields or change enum variants without versioning the schema.

## Definition of done

- `cargo build` and `cargo test` are clean.
- `cargo run -p aloo-bench` shows no regression in precision, recall, or false-positive rate.
- New detection has a malicious fixture and a benign counter-fixture.
- No new heavy dependency without justification, and nothing oxc-specific crossed the `Analyzer` boundary.
- The verdict schema is unchanged or explicitly versioned.
- Changes to `aloo-intelligence` do not touch `decision` in the stored `Verdict`.
- No comments were added.