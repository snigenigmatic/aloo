use crate::model::{Evidence, PackageFacts, Reason, ReasonCode, Severity};

const EVIDENCE_CAP: usize = 10;

pub fn run(facts: &PackageFacts) -> Vec<Reason> {
    let mut endpoint_evidence = facts
        .endpoints()
        .map(|observation| observation.evidence.clone())
        .collect::<Vec<Evidence>>();
    endpoint_evidence.sort();
    endpoint_evidence.dedup();
    endpoint_evidence.truncate(EVIDENCE_CAP);

    let mut decoded_eval_evidence = facts
        .decoded_evals()
        .map(|observation| observation.evidence.clone())
        .collect::<Vec<Evidence>>();
    decoded_eval_evidence.sort();
    decoded_eval_evidence.dedup();
    decoded_eval_evidence.truncate(EVIDENCE_CAP);

    let mut reasons = Vec::new();

    if !endpoint_evidence.is_empty() {
        reasons.push(Reason {
            code: ReasonCode::KnownIoc,
            severity: Severity::High,
            title: "Known exfiltration endpoint referenced".to_string(),
            detail: "The package references a Discord webhook or Telegram bot endpoint used as a destination for stolen data.".to_string(),
            evidence: endpoint_evidence,
        });
    }

    if !decoded_eval_evidence.is_empty() {
        reasons.push(Reason {
            code: ReasonCode::DynamicEval,
            severity: Severity::High,
            title: "Dynamic evaluation of decoded payload".to_string(),
            detail: "The package evaluates a decoded payload through eval(atob(...)), eval(Buffer.from(...)), or eval(unescape(...)).".to_string(),
            evidence: decoded_eval_evidence,
        });
    }

    reasons
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{
        DecodedEvalKind, DecodedEvalObs, EndpointKind, EndpointObs, Evidence, FileFacts,
        PackageFacts,
    };

    fn facts(endpoints: Vec<EndpointObs>, decoded_evals: Vec<DecodedEvalObs>) -> PackageFacts {
        PackageFacts {
            files: vec![FileFacts {
                path: "src/index.js".to_string(),
                lifecycle_scripts: Vec::new(),
                encoded_literals: Vec::new(),
                endpoints,
                decoded_evals,
                sources: Vec::new(),
                sinks: Vec::new(),
                flows: Vec::new(),
            }],
        }
    }

    fn endpoint(kind: EndpointKind, line: usize) -> EndpointObs {
        EndpointObs {
            kind,
            evidence: Evidence {
                file: "src/index.js".to_string(),
                line,
                snippet: format!("endpoint on line {line}"),
            },
        }
    }

    fn decoded_eval(kind: DecodedEvalKind, line: usize) -> DecodedEvalObs {
        DecodedEvalObs {
            kind,
            evidence: Evidence {
                file: "src/index.js".to_string(),
                line,
                snippet: format!("decoded eval on line {line}"),
            },
        }
    }

    #[test]
    fn discord_webhook_emits_known_ioc_reason() {
        let reasons = run(&facts(
            vec![endpoint(EndpointKind::DiscordWebhook, 1)],
            Vec::new(),
        ));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, ReasonCode::KnownIoc);
        assert_eq!(reasons[0].severity, Severity::High);
        assert_eq!(reasons[0].evidence.len(), 1);
    }

    #[test]
    fn telegram_and_discord_combine_into_one_known_ioc_reason() {
        let reasons = run(&facts(
            vec![
                endpoint(EndpointKind::DiscordWebhook, 1),
                endpoint(EndpointKind::TelegramBot, 2),
            ],
            Vec::new(),
        ));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, ReasonCode::KnownIoc);
        assert_eq!(reasons[0].evidence.len(), 2);
    }

    #[test]
    fn decoded_eval_emits_dynamic_eval_reason() {
        let reasons = run(&facts(
            Vec::new(),
            vec![decoded_eval(DecodedEvalKind::Atob, 1)],
        ));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, ReasonCode::DynamicEval);
        assert_eq!(reasons[0].severity, Severity::High);
    }

    #[test]
    fn endpoints_and_decoded_evals_emit_separate_reasons() {
        let reasons = run(&facts(
            vec![endpoint(EndpointKind::DiscordWebhook, 1)],
            vec![decoded_eval(DecodedEvalKind::Atob, 2)],
        ));

        assert_eq!(reasons.len(), 2);
        assert!(
            reasons
                .iter()
                .any(|reason| reason.code == ReasonCode::KnownIoc)
        );
        assert!(
            reasons
                .iter()
                .any(|reason| reason.code == ReasonCode::DynamicEval)
        );
    }

    #[test]
    fn no_observations_emit_no_reasons() {
        let reasons = run(&facts(Vec::new(), Vec::new()));

        assert!(reasons.is_empty());
    }

    #[test]
    fn endpoint_evidence_is_capped_at_ten_entries() {
        let endpoints = (1..=15)
            .map(|line| endpoint(EndpointKind::DiscordWebhook, line))
            .collect();

        let reasons = run(&facts(endpoints, Vec::new()));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].evidence.len(), 10);
        assert_eq!(reasons[0].evidence[0].line, 1);
        assert_eq!(reasons[0].evidence[9].line, 10);
    }

    #[test]
    fn decoded_eval_evidence_is_capped_at_ten_entries() {
        let decoded_evals = (1..=15)
            .map(|line| decoded_eval(DecodedEvalKind::Atob, line))
            .collect();

        let reasons = run(&facts(Vec::new(), decoded_evals));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].evidence.len(), 10);
    }
}
