use crate::model::{
    FlowObs, PackageFacts, Reason, ReasonCode, Sensitivity, Severity, SinkKind, SourceKind,
};

pub fn run(facts: &PackageFacts) -> Vec<Reason> {
    let mut reasons = facts.flows().map(reason_for_flow).collect::<Vec<_>>();

    reasons.sort_by(|left, right| {
        left.severity
            .cmp(&right.severity)
            .then(left.title.cmp(&right.title))
            .then(left.detail.cmp(&right.detail))
            .then(left.evidence.cmp(&right.evidence))
    });

    reasons
}

fn reason_for_flow(flow: &FlowObs) -> Reason {
    let severity = match flow.source.sensitivity() {
        Sensitivity::Critical => Severity::Critical,
        Sensitivity::Elevated => Severity::High,
    };

    Reason {
        code: ReasonCode::CredentialExfiltration,
        severity,
        title: format!(
            "{} reaches {}",
            source_label(flow.source),
            sink_label(flow.sink)
        ),
        detail: format!(
            "The package reads {} and sends it to a {} sink.",
            source_detail(flow.source),
            sink_detail(flow.sink)
        ),
        evidence: vec![flow.evidence.clone()],
    }
}

fn source_label(source: SourceKind) -> &'static str {
    match source {
        SourceKind::ProcessEnv => "process environment data",
        SourceKind::EnvFile => "environment file data",
        SourceKind::NpmToken => "npm auth token",
        SourceKind::SshKey => "SSH key material",
        SourceKind::AwsCredentials => "AWS credentials",
        SourceKind::WalletData => "wallet data",
        SourceKind::BrowserData => "browser profile data",
    }
}

fn sink_label(sink: SinkKind) -> &'static str {
    match sink {
        SinkKind::NetworkSend => "network",
        SinkKind::ProcessExec => "process execution",
        SinkKind::DynamicEval => "dynamic evaluation",
        SinkKind::FilesystemWrite => "filesystem write",
    }
}

fn source_detail(source: SourceKind) -> &'static str {
    match source {
        SourceKind::ProcessEnv => "process environment variables",
        SourceKind::EnvFile => "an environment file",
        SourceKind::NpmToken => "an npm auth token",
        SourceKind::SshKey => "SSH key material",
        SourceKind::AwsCredentials => "AWS credentials",
        SourceKind::WalletData => "wallet data",
        SourceKind::BrowserData => "browser profile data",
    }
}

fn sink_detail(sink: SinkKind) -> &'static str {
    match sink {
        SinkKind::NetworkSend => "network",
        SinkKind::ProcessExec => "process execution",
        SinkKind::DynamicEval => "dynamic evaluation",
        SinkKind::FilesystemWrite => "filesystem write",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, FileFacts, PackageFacts};

    fn flow(source: SourceKind, sink: SinkKind, line: usize) -> FlowObs {
        FlowObs {
            source,
            sink,
            evidence: Evidence {
                file: "src/index.js".to_string(),
                line,
                snippet: format!("flow on line {line}"),
            },
        }
    }

    fn facts(flows: Vec<FlowObs>) -> PackageFacts {
        PackageFacts {
            files: vec![FileFacts {
                path: "src/index.js".to_string(),
                lifecycle_scripts: Vec::new(),
                encoded_literals: Vec::new(),
                endpoints: Vec::new(),
                decoded_evals: Vec::new(),
                sources: Vec::new(),
                sinks: Vec::new(),
                flows,
            }],
        }
    }

    #[test]
    fn npm_token_to_network_is_critical() {
        let reasons = run(&facts(vec![flow(
            SourceKind::NpmToken,
            SinkKind::NetworkSend,
            1,
        )]));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, ReasonCode::CredentialExfiltration);
        assert_eq!(reasons[0].severity, Severity::Critical);
        assert_eq!(reasons[0].evidence[0].line, 1);
    }

    #[test]
    fn process_env_to_network_is_high() {
        let reasons = run(&facts(vec![flow(
            SourceKind::ProcessEnv,
            SinkKind::NetworkSend,
            2,
        )]));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, ReasonCode::CredentialExfiltration);
        assert_eq!(reasons[0].severity, Severity::High);
    }

    #[test]
    fn ssh_key_to_process_exec_is_critical() {
        let reasons = run(&facts(vec![flow(
            SourceKind::SshKey,
            SinkKind::ProcessExec,
            3,
        )]));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].severity, Severity::Critical);
    }

    #[test]
    fn no_flows_emit_no_reasons() {
        let reasons = run(&PackageFacts { files: Vec::new() });

        assert!(reasons.is_empty());
    }

    #[test]
    fn multiple_flows_emit_one_reason_each() {
        let reasons = run(&facts(vec![
            flow(SourceKind::NpmToken, SinkKind::NetworkSend, 1),
            flow(SourceKind::ProcessEnv, SinkKind::NetworkSend, 2),
        ]));

        assert_eq!(reasons.len(), 2);
    }
}
