use crate::model::{Decision, Reason, Severity};

pub const WARN_THRESHOLD: u32 = 15;
pub const BLOCK_THRESHOLD: u32 = 100;

pub fn score_reasons(reasons: &[Reason]) -> (Decision, u32) {
    let score = reasons
        .iter()
        .map(|reason| severity_weight(reason.severity))
        .sum();

    if reasons
        .iter()
        .any(|reason| reason.severity == Severity::Critical)
    {
        (Decision::Block, score)
    } else if score >= BLOCK_THRESHOLD {
        (Decision::Block, score)
    } else if score >= WARN_THRESHOLD {
        (Decision::Warn, score)
    } else {
        (Decision::Allow, score)
    }
}

pub fn severity_weight(severity: Severity) -> u32 {
    match severity {
        Severity::Info => 0,
        Severity::Low => 5,
        Severity::Medium => 15,
        Severity::High => 40,
        Severity::Critical => 100,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Evidence, ReasonCode};

    fn reason(severity: Severity) -> Reason {
        Reason {
            code: ReasonCode::Obfuscation,
            severity,
            title: String::new(),
            detail: String::new(),
            evidence: vec![Evidence {
                file: "x.js".to_string(),
                line: 1,
                snippet: "x".to_string(),
            }],
        }
    }

    #[test]
    fn threshold_boundaries_hold() {
        assert_eq!(score_reasons(&[]), (Decision::Allow, 0));
        assert_eq!(
            score_reasons(&[reason(Severity::Medium)]),
            (Decision::Warn, 15)
        );
        assert_eq!(
            score_reasons(&[
                reason(Severity::High),
                reason(Severity::High),
                reason(Severity::Medium),
                reason(Severity::Low)
            ]),
            (Decision::Block, 100)
        );
        assert_eq!(
            score_reasons(&[reason(Severity::Critical)]),
            (Decision::Block, 100)
        );
    }
}
