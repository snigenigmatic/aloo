use crate::model::{Evidence, PackageFacts, Reason, ReasonCode, Severity};

const EVIDENCE_CAP: usize = 20;

pub fn run(facts: &PackageFacts) -> Vec<Reason> {
    let mut evidence = facts
        .encoded_literals()
        .map(|observation| observation.evidence.clone())
        .collect::<Vec<Evidence>>();

    evidence.sort();
    evidence.dedup();
    evidence.truncate(EVIDENCE_CAP);

    if evidence.is_empty() {
        return Vec::new();
    }

    vec![Reason {
        code: ReasonCode::Obfuscation,
        severity: Severity::Medium,
        title: "Obfuscated or encoded code detected".to_string(),
        detail: "The package contains base64 blobs, chained fromCharCode calls, or high-entropy string literals.".to_string(),
        evidence,
    }]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{EncodedLiteralKind, EncodedLiteralObs, Evidence, FileFacts, PackageFacts};

    fn facts(observations: Vec<EncodedLiteralObs>) -> PackageFacts {
        PackageFacts {
            files: vec![FileFacts {
                path: "src/index.js".to_string(),
                lifecycle_scripts: Vec::new(),
                encoded_literals: observations,
                sources: Vec::new(),
                sinks: Vec::new(),
                flows: Vec::new(),
            }],
        }
    }

    fn observation(kind: EncodedLiteralKind, line: usize) -> EncodedLiteralObs {
        EncodedLiteralObs {
            kind,
            evidence: Evidence {
                file: "src/index.js".to_string(),
                line,
                snippet: format!("encoded literal on line {line}"),
            },
        }
    }

    #[test]
    fn encoded_literals_emit_single_obfuscation_reason() {
        let reasons = run(&facts(vec![
            observation(EncodedLiteralKind::Base64Blob, 1),
            observation(EncodedLiteralKind::FromCharCodeChain, 2),
        ]));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].code, ReasonCode::Obfuscation);
        assert_eq!(reasons[0].severity, Severity::Medium);
        assert_eq!(reasons[0].evidence.len(), 2);
    }

    #[test]
    fn no_encoded_literals_emit_no_reasons() {
        let reasons = run(&PackageFacts { files: Vec::new() });

        assert!(reasons.is_empty());
    }

    #[test]
    fn evidence_is_capped_at_twenty_entries() {
        let observations = (1..=25)
            .map(|line| observation(EncodedLiteralKind::Base64Blob, line))
            .collect();

        let reasons = run(&facts(observations));

        assert_eq!(reasons.len(), 1);
        assert_eq!(reasons[0].evidence.len(), 20);
        assert_eq!(reasons[0].evidence[0].line, 1);
        assert_eq!(reasons[0].evidence[19].line, 20);
    }
}
