# aloo

aloo is a supply-chain safety context for statically vetting npm package artifacts before installation or execution.

## Language

**Verdict**:
The structured safety decision for one package version, including the decision, score, reasons, analyzer identity, and evidence an agent or human can inspect.
_Avoid_: Result, report, scan output

**Engine**:
The deterministic decision maker that produces a Verdict from package facts and detection reasons through one verdict assembly seam.
_Avoid_: Scanner, runner, orchestrator

**Package artifact**:
The package directory or tarball bytes that would actually be installed or executed.
_Avoid_: Repository, source checkout, project

**Analyzer**:
The static fact extractor for a package artifact. Analyzer adapters can vary in implementation strategy, but they produce the same package facts interface.
_Avoid_: Parser, scanner, backend

**Analyzer adapter**:
A concrete analyzer implementation such as the heuristic or oxc-backed adapter. The caller chooses the adapter; the Engine depends only on the Analyzer interface.
_Avoid_: Mode, scanner type, runtime flag

**Package facts**:
The complete static fact interface emitted by an Analyzer and consumed by detection signals. Package facts may store observations by file internally, but signals consume package-level facts and iterators rather than raw source scanning.
_Avoid_: Raw files, scan output, parsed code

**Signal**:
A fact-to-reason module that turns package facts into deterministic findings. Signals do not scan package contents directly.
_Avoid_: Detector, scanner rule, parser

**Loader**:
The package artifact adapter that turns a local directory or tarball path into a PackageVersion with all loader invariants applied.
_Avoid_: File walker, tarball helper, repository reader

**Reason**:
A deterministic, machine-actionable finding that explains why a Verdict scored the way it did. Reasons use a closed code taxonomy and inspectable evidence.
_Avoid_: Explanation, narrative, model output

**Enrichment**:
A human-facing narrative generated after a Verdict exists. Enrichment may explain or assess a Verdict, but it never changes the Verdict's decision, score, severity, reason codes, or evidence.
_Avoid_: Verdict, reason, decision

**Reason taxonomy**:
The closed set of machine-actionable reason codes used in deterministic verdicts. Expanding the taxonomy is a deliberate schema change.
_Avoid_: Freeform label, model explanation, narrative category
