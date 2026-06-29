use crate::analyzer::Analyzer;
use crate::model::{
    EncodedLiteralKind, EncodedLiteralObs, FileFacts, FlowObs, LifecycleScriptObs, PackageFacts,
    PackageVersion, SinkKind, SinkObs, SourceKind, SourceObs, evidence,
};
use regex::Regex;
use std::collections::BTreeMap;
use std::sync::OnceLock;

pub struct HeuristicAnalyzer;

impl Analyzer for HeuristicAnalyzer {
    fn name(&self) -> &str {
        "heuristic"
    }

    fn analyze_package(&self, pkg: &PackageVersion) -> PackageFacts {
        let mut files = lifecycle_file_facts(pkg)
            .into_iter()
            .chain(pkg.files.iter().filter_map(|file| {
                if is_package_json(&file.path) {
                    return None;
                }

                let mut sources = Vec::new();
                let mut sinks = Vec::new();
                let mut encoded_literals = Vec::new();

                for (index, line) in file.contents.lines().enumerate() {
                    let line_number = index + 1;

                    for (kind, pattern) in source_patterns() {
                        if pattern.is_match(line) {
                            sources.push(SourceObs {
                                kind: *kind,
                                evidence: evidence(&file.path, line_number, line),
                            });
                        }
                    }

                    for (kind, pattern) in sink_patterns() {
                        if pattern.is_match(line) {
                            sinks.push(SinkObs {
                                kind: *kind,
                                evidence: evidence(&file.path, line_number, line),
                            });
                        }
                    }

                    encoded_literals.extend(extract_encoded_literals(
                        &file.path,
                        line_number,
                        line,
                    ));
                }

                sources.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.evidence.cmp(&b.evidence)));
                sinks.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.evidence.cmp(&b.evidence)));
                encoded_literals.sort();
                encoded_literals.dedup();
                sources.dedup_by(|a, b| a.kind == b.kind && a.evidence == b.evidence);
                sinks.dedup_by(|a, b| a.kind == b.kind && a.evidence == b.evidence);

                let flows = infer_flows(&sources, &sinks);

                if sources.is_empty() && sinks.is_empty() && encoded_literals.is_empty() {
                    None
                } else {
                    Some(FileFacts {
                        path: file.path.clone(),
                        lifecycle_scripts: Vec::new(),
                        encoded_literals,
                        sources,
                        sinks,
                        flows,
                    })
                }
            }))
            .collect::<Vec<_>>();

        files.sort_by(|a, b| a.path.cmp(&b.path));

        PackageFacts { files }
    }
}

fn lifecycle_file_facts(pkg: &PackageVersion) -> Option<FileFacts> {
    let mut lifecycle_scripts = pkg
        .lifecycle_scripts()
        .map(|(hook, command)| LifecycleScriptObs {
            hook,
            command: command.to_string(),
            evidence: evidence(
                "package.json",
                manifest_line(&pkg.manifest.raw, hook.as_str()),
                format!("\"{}\": \"{}\"", hook.as_str(), command),
            ),
        })
        .collect::<Vec<_>>();

    lifecycle_scripts.sort();
    lifecycle_scripts.dedup();

    if lifecycle_scripts.is_empty() {
        None
    } else {
        Some(FileFacts {
            path: "package.json".to_string(),
            lifecycle_scripts,
            encoded_literals: Vec::new(),
            sources: Vec::new(),
            sinks: Vec::new(),
            flows: Vec::new(),
        })
    }
}

fn manifest_line(raw: &str, hook: &str) -> usize {
    let key = format!("\"{hook}\":");
    raw.lines()
        .position(|line| line.contains(&key))
        .map(|index| index + 1)
        .unwrap_or(1)
}

fn is_package_json(path: &str) -> bool {
    path == "package.json" || path.ends_with("/package.json") || path.ends_with("\\package.json")
}

const MIN_BASE64_LEN: usize = 200;
const MIN_HIGH_ENTROPY_LITERAL_LEN: usize = 120;
const HIGH_ENTROPY_THRESHOLD: f64 = 4.5;
const MIN_FROM_CHAR_CODE_CALLS: usize = 4;

fn extract_encoded_literals(path: &str, line_number: usize, line: &str) -> Vec<EncodedLiteralObs> {
    let mut observations = Vec::new();

    for pattern in base64_patterns() {
        for matched in pattern.find_iter(line) {
            if matched.as_str().len() >= MIN_BASE64_LEN {
                observations.push(EncodedLiteralObs {
                    kind: EncodedLiteralKind::Base64Blob,
                    evidence: evidence(path, line_number, line),
                });
                break;
            }
        }
    }

    if from_char_code_pattern().find_iter(line).count() >= MIN_FROM_CHAR_CODE_CALLS {
        observations.push(EncodedLiteralObs {
            kind: EncodedLiteralKind::FromCharCodeChain,
            evidence: evidence(path, line_number, line),
        });
    }

    for literal in quoted_literals(line) {
        if literal.chars().count() >= MIN_HIGH_ENTROPY_LITERAL_LEN
            && shannon_entropy(literal) > HIGH_ENTROPY_THRESHOLD
        {
            observations.push(EncodedLiteralObs {
                kind: EncodedLiteralKind::HighEntropyLiteral,
                evidence: evidence(path, line_number, line),
            });
            break;
        }
    }

    observations
}

fn quoted_literals(line: &str) -> Vec<&str> {
    let mut literals = Vec::new();
    let bytes = line.as_bytes();
    let mut index = 0;

    while index < bytes.len() {
        let quote = bytes[index];
        if quote == b'"' || quote == b'\'' {
            let start = index + 1;
            index += 1;
            while index < bytes.len() && bytes[index] != quote {
                if bytes[index] == b'\\' && index + 1 < bytes.len() {
                    index += 2;
                } else {
                    index += 1;
                }
            }
            if index < bytes.len() {
                literals.push(&line[start..index]);
            }
            index += 1;
        } else {
            index += 1;
        }
    }

    literals
}

fn shannon_entropy(value: &str) -> f64 {
    if value.is_empty() {
        return 0.0;
    }

    let mut counts = BTreeMap::<char, usize>::new();
    for ch in value.chars() {
        *counts.entry(ch).or_default() += 1;
    }

    let length = value.chars().count() as f64;
    counts
        .values()
        .map(|count| {
            let probability = *count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}

fn base64_patterns() -> &'static [Regex] {
    static BASE64_PATTERNS: OnceLock<Vec<Regex>> = OnceLock::new();
    BASE64_PATTERNS
        .get_or_init(|| vec![Regex::new(r"[A-Za-z0-9+/]{200,}={0,2}").unwrap()])
        .as_slice()
}

fn from_char_code_pattern() -> &'static Regex {
    static FROM_CHAR_CODE_PATTERN: OnceLock<Regex> = OnceLock::new();
    FROM_CHAR_CODE_PATTERN.get_or_init(|| Regex::new(r"String\.fromCharCode\s*\(").unwrap())
}

fn source_patterns() -> &'static [(SourceKind, Regex)] {
    static SOURCE_PATTERNS: OnceLock<Vec<(SourceKind, Regex)>> = OnceLock::new();
    SOURCE_PATTERNS
        .get_or_init(|| {
            vec![
                (
                    SourceKind::ProcessEnv,
                    Regex::new(r"process\s*\.\s*env").unwrap(),
                ),
                (
                    SourceKind::NpmToken,
                    Regex::new(r"\.npmrc|NPM_TOKEN|_authToken").unwrap(),
                ),
                (
                    SourceKind::SshKey,
                    Regex::new(r"\.ssh/|\.ssh\\|id_rsa").unwrap(),
                ),
                (
                    SourceKind::AwsCredentials,
                    Regex::new(r"\.aws/credentials|\.aws\\credentials|AWS_SECRET_ACCESS_KEY")
                        .unwrap(),
                ),
                (
                    SourceKind::EnvFile,
                    Regex::new(r#"["'`][^"'`]*\.env(?:\.[^"'`]*)?["'`]"#).unwrap(),
                ),
                (
                    SourceKind::WalletData,
                    Regex::new(r"wallet\.dat|keystore|MetaMask").unwrap(),
                ),
                (
                    SourceKind::BrowserData,
                    Regex::new(
                        r"(?:Chrome|Chromium|Brave|Edge|User Data|Default|Profile [0-9]+)/.*(?:Login Data|Cookies|leveldb)",
                    )
                    .unwrap(),
                ),
            ]
        })
        .as_slice()
}

fn sink_patterns() -> &'static [(SinkKind, Regex)] {
    static SINK_PATTERNS: OnceLock<Vec<(SinkKind, Regex)>> = OnceLock::new();
    SINK_PATTERNS
        .get_or_init(|| {
            vec![
                (
                    SinkKind::NetworkSend,
                    Regex::new(
                        r"fetch\s*\(|https?\.request|axios|net\.connect|WebSocket\s*\(|(?:axios|got|request|superagent|needle|httpClient|httpsClient)\s*\.\s*post\s*\(|dns\.",
                    )
                    .unwrap(),
                ),
                (
                    SinkKind::ProcessExec,
                    Regex::new(
                        r"child_process|execSync\s*\(|(?:^|[^.$\w])exec\s*\(|spawn\s*\(|execFile\s*\(",
                    )
                    .unwrap(),
                ),
                (
                    SinkKind::DynamicEval,
                    Regex::new(r"eval\s*\(|new\s+Function\s*\(|vm\.runIn").unwrap(),
                ),
                (
                    SinkKind::FilesystemWrite,
                    Regex::new(r"writeFileSync\s*\(|createWriteStream\s*\(").unwrap(),
                ),
            ]
        })
        .as_slice()
}

fn infer_flows(sources: &[SourceObs], sinks: &[SinkObs]) -> Vec<FlowObs> {
    let mut source_evidence = BTreeMap::new();
    let mut sink_kinds = BTreeMap::new();

    for source in sources {
        source_evidence
            .entry(source.kind)
            .or_insert_with(|| source.evidence.clone());
    }

    for sink in sinks {
        sink_kinds.entry(sink.kind).or_insert(());
    }

    let mut flows = Vec::new();
    for (source, evidence) in source_evidence {
        for sink in sink_kinds.keys() {
            flows.push(FlowObs {
                source,
                sink: *sink,
                evidence: evidence.clone(),
            });
        }
    }

    flows.sort();
    flows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EncodedLiteralKind, Manifest, PackageVersion, SourceFile};
    use std::collections::BTreeMap;

    fn package(contents: &str) -> PackageVersion {
        PackageVersion {
            name: "case".to_string(),
            version: "1.0.0".to_string(),
            manifest: Manifest {
                name: "case".to_string(),
                version: "1.0.0".to_string(),
                scripts: BTreeMap::new(),
                raw: "{}".to_string(),
            },
            files: vec![SourceFile {
                path: "src/index.js".to_string(),
                contents: contents.to_string(),
            }],
        }
    }

    fn package_facts(contents: &str) -> PackageFacts {
        HeuristicAnalyzer.analyze_package(&package(contents))
    }

    fn first_file_facts(contents: &str) -> FileFacts {
        package_facts(contents).files.into_iter().next().unwrap()
    }

    #[test]
    fn name_is_heuristic() {
        assert_eq!(HeuristicAnalyzer.name(), "heuristic");
    }

    #[test]
    fn env_plus_fetch_yields_flow() {
        let facts = first_file_facts(
            "const secret = process.env.SECRET_VALUE;\nfetch('https://example.invalid', { body: secret });",
        );

        assert_eq!(facts.flows.len(), 1);
        assert_eq!(facts.flows[0].source, SourceKind::ProcessEnv);
        assert_eq!(facts.flows[0].sink, SinkKind::NetworkSend);
    }

    #[test]
    fn env_plus_exec_yields_flow() {
        let facts = first_file_facts(
            "const key = process.env.AWS_SECRET_ACCESS_KEY;\nexecSync('aws configure set secret ' + key);",
        );

        assert!(
            facts
                .flows
                .iter()
                .any(|flow| flow.source == SourceKind::AwsCredentials
                    && flow.sink == SinkKind::ProcessExec)
        );
    }

    #[test]
    fn env_plus_eval_yields_flow() {
        let facts = first_file_facts("const value = process.env.SECRET;\neval(value);");

        assert!(facts.flows.iter().any(
            |flow| flow.source == SourceKind::ProcessEnv && flow.sink == SinkKind::DynamicEval
        ));
    }

    #[test]
    fn env_alone_yields_source_without_flow() {
        let facts = first_file_facts("const secret = process.env.SECRET_VALUE;");

        assert_eq!(facts.sources.len(), 1);
        assert_eq!(facts.sources[0].kind, SourceKind::ProcessEnv);
        assert!(facts.sinks.is_empty());
        assert!(facts.flows.is_empty());
    }

    #[test]
    fn fetch_alone_yields_sink_without_flow() {
        let facts = first_file_facts("fetch('https://example.invalid/ping');");

        assert!(facts.sources.is_empty());
        assert_eq!(facts.sinks.len(), 1);
        assert_eq!(facts.sinks[0].kind, SinkKind::NetworkSend);
        assert!(facts.flows.is_empty());
    }

    #[test]
    fn evidence_carries_file_path_and_line_number() {
        let facts = first_file_facts(
            "const ok = true;\nconst secret = process.env.SECRET_VALUE;\nfetch('https://example.invalid', { body: secret });",
        );

        assert_eq!(facts.sources[0].evidence.file, "src/index.js");
        assert_eq!(facts.sources[0].evidence.line, 2);
        assert_eq!(facts.sinks[0].evidence.file, "src/index.js");
        assert_eq!(facts.sinks[0].evidence.line, 3);
    }

    #[test]
    fn source_patterns_cover_expected_vocabulary() {
        let cases = [
            (SourceKind::ProcessEnv, "const value = process.env.SECRET;"),
            (SourceKind::NpmToken, "const value = '_authToken=abc';"),
            (SourceKind::SshKey, "const value = '/home/me/.ssh/id_rsa';"),
            (
                SourceKind::AwsCredentials,
                "const value = 'AWS_SECRET_ACCESS_KEY';",
            ),
            (SourceKind::EnvFile, "fs.readFileSync('.env');"),
            (SourceKind::WalletData, "const value = 'wallet.dat';"),
            (
                SourceKind::BrowserData,
                "const value = 'Chrome/User Data/Default/Login Data';",
            ),
        ];

        for (expected, contents) in cases {
            let facts = first_file_facts(contents);
            assert!(
                facts.sources.iter().any(|source| source.kind == expected),
                "missing source kind {expected:?} for {contents}"
            );
        }
    }

    #[test]
    fn sink_patterns_cover_expected_vocabulary() {
        let cases = [
            (SinkKind::NetworkSend, "fetch('https://example.invalid');"),
            (SinkKind::NetworkSend, "https.request(options);"),
            (SinkKind::NetworkSend, "axios.post('/event');"),
            (
                SinkKind::NetworkSend,
                "net.connect(443, 'example.invalid');",
            ),
            (
                SinkKind::NetworkSend,
                "new WebSocket('wss://example.invalid');",
            ),
            (SinkKind::NetworkSend, "httpClient.post('/event');"),
            (SinkKind::NetworkSend, "dns.lookup('example.invalid');"),
            (SinkKind::ProcessExec, "child_process.exec('echo ok');"),
            (SinkKind::ProcessExec, "execSync('echo ok');"),
            (SinkKind::ProcessExec, "exec('echo ok');"),
            (SinkKind::ProcessExec, "spawn('node');"),
            (SinkKind::ProcessExec, "execFile('node');"),
            (SinkKind::DynamicEval, "eval(payload);"),
            (SinkKind::DynamicEval, "new Function(payload);"),
            (SinkKind::DynamicEval, "vm.runInNewContext(payload);"),
            (SinkKind::FilesystemWrite, "fs.writeFileSync(path, data);"),
            (SinkKind::FilesystemWrite, "fs.createWriteStream(path);"),
        ];

        for (expected, contents) in cases {
            let facts = first_file_facts(contents);
            assert!(
                facts.sinks.iter().any(|sink| sink.kind == expected),
                "missing sink kind {expected:?} for {contents}"
            );
        }
    }

    #[test]
    fn broad_post_and_regex_exec_do_not_trigger_sinks() {
        let facts =
            package_facts("router.post('/route', handler);\nconst found = /x/.exec(value);");

        assert!(facts.files.is_empty());
    }

    #[test]
    fn generic_cookie_text_does_not_trigger_browser_data() {
        let facts = package_facts("const label = 'Cookies';\ndocument.cookie = 'a=b';");

        assert!(facts.files.is_empty());
    }

    #[test]
    fn repeated_source_kind_produces_one_flow_per_sink_kind() {
        let facts = first_file_facts(
            "const a = process.env.A;\nconst b = process.env.B;\nfetch('https://example.invalid', { body: a + b });",
        );

        assert_eq!(facts.flows.len(), 1);
        assert_eq!(facts.flows[0].source, SourceKind::ProcessEnv);
        assert_eq!(facts.flows[0].sink, SinkKind::NetworkSend);
    }

    #[test]
    fn manifest_line_targets_scripts_key_not_keywords() {
        let raw = r#"{
  "name": "case",
  "keywords": ["install", "native"],
  "scripts": {
    "postinstall": "node index.js"
  }
}"#;
        assert_eq!(manifest_line(raw, "postinstall"), 5);
    }

    #[test]
    fn lifecycle_script_evidence_uses_scripts_line() {
        let mut scripts = BTreeMap::new();
        scripts.insert("postinstall".to_string(), "node index.js".to_string());
        let raw = r#"{
  "name": "case",
  "keywords": ["install"],
  "scripts": {
    "postinstall": "node index.js"
  }
}"#;
        let pkg = PackageVersion {
            name: "case".to_string(),
            version: "1.0.0".to_string(),
            manifest: Manifest {
                name: "case".to_string(),
                version: "1.0.0".to_string(),
                scripts,
                raw: raw.to_string(),
            },
            files: Vec::new(),
        };

        let facts = HeuristicAnalyzer.analyze_package(&pkg);
        let lifecycle = facts
            .files
            .iter()
            .find(|file| file.path == "package.json")
            .unwrap();

        assert_eq!(lifecycle.lifecycle_scripts.len(), 1);
        assert_eq!(lifecycle.lifecycle_scripts[0].evidence.line, 5);
    }

    fn package_with_files(files: Vec<SourceFile>) -> PackageVersion {
        PackageVersion {
            name: "case".to_string(),
            version: "1.0.0".to_string(),
            manifest: Manifest {
                name: "case".to_string(),
                version: "1.0.0".to_string(),
                scripts: BTreeMap::new(),
                raw: "{}".to_string(),
            },
            files,
        }
    }

    #[test]
    fn base64_blob_emits_encoded_literal_observation() {
        let blob = "A".repeat(200);
        let facts = HeuristicAnalyzer.analyze_package(&package_with_files(vec![SourceFile {
            path: "src/index.js".to_string(),
            contents: format!("const payload = \"{blob}\";"),
        }]));

        let file = facts.files.into_iter().next().unwrap();
        assert_eq!(file.encoded_literals.len(), 1);
        assert_eq!(
            file.encoded_literals[0].kind,
            EncodedLiteralKind::Base64Blob
        );
    }

    #[test]
    fn from_char_code_chain_emits_encoded_literal_observation() {
        let contents = "const x = String.fromCharCode(65)+String.fromCharCode(66)+String.fromCharCode(67)+String.fromCharCode(68);";
        let facts = HeuristicAnalyzer.analyze_package(&package_with_files(vec![SourceFile {
            path: "src/index.js".to_string(),
            contents: contents.to_string(),
        }]));

        let file = facts.files.into_iter().next().unwrap();
        assert_eq!(file.encoded_literals.len(), 1);
        assert_eq!(
            file.encoded_literals[0].kind,
            EncodedLiteralKind::FromCharCodeChain
        );
    }

    #[test]
    fn high_entropy_literal_emits_encoded_literal_observation() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let literal: String = alphabet.chars().cycle().take(128).collect();
        let facts = HeuristicAnalyzer.analyze_package(&package_with_files(vec![SourceFile {
            path: "src/index.js".to_string(),
            contents: format!("const payload = \"{literal}\";"),
        }]));

        let file = facts.files.into_iter().next().unwrap();
        assert_eq!(file.encoded_literals.len(), 1);
        assert_eq!(
            file.encoded_literals[0].kind,
            EncodedLiteralKind::HighEntropyLiteral
        );
    }

    #[test]
    fn short_high_entropy_literal_emits_no_observation() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let literal: String = alphabet.chars().cycle().take(119).collect();
        let facts = HeuristicAnalyzer.analyze_package(&package_with_files(vec![SourceFile {
            path: "src/index.js".to_string(),
            contents: format!("const payload = \"{literal}\";"),
        }]));

        assert!(facts.files.is_empty());
    }

    #[test]
    fn readable_literal_emits_no_observation() {
        let literal = "The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog. The quick brown fox jumps over the lazy dog.";
        let facts = HeuristicAnalyzer.analyze_package(&package_with_files(vec![SourceFile {
            path: "src/index.js".to_string(),
            contents: format!("const message = \"{literal}\";"),
        }]));

        assert!(facts.files.is_empty());
    }

    #[test]
    fn package_json_is_excluded_from_entropy_extraction() {
        let blob = "A".repeat(200);
        let facts = HeuristicAnalyzer.analyze_package(&package_with_files(vec![SourceFile {
            path: "package.json".to_string(),
            contents: format!("{{\"description\": \"{blob}\"}}"),
        }]));

        assert!(facts.files.is_empty());
    }

    #[test]
    fn shannon_entropy_of_uniform_alphabet_is_high() {
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let value: String = alphabet.chars().cycle().take(128).collect();
        assert!(shannon_entropy(&value) > 4.5);
    }
}
