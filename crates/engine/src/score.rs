use crate::model::{Decision, Reason, Severity};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoreConfig {
    pub warn_threshold: u32,
    pub block_threshold: u32,
}

impl Default for ScoreConfig {
    fn default() -> Self {
        Self {
            warn_threshold: 15,
            block_threshold: 100,
        }
    }
}

pub fn score_reasons(reasons: &[Reason]) -> (Decision, u32) {
    score_reasons_with_config(reasons, ScoreConfig::default())
}

pub fn score_reasons_with_config(reasons: &[Reason], config: ScoreConfig) -> (Decision, u32) {
    let score = reasons
        .iter()
        .map(|reason| severity_weight(reason.severity))
        .sum();

    if reasons
        .iter()
        .any(|reason| reason.severity == Severity::Critical)
        || score >= config.block_threshold
    {
        (Decision::Block, score)
    } else if score >= config.warn_threshold {
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
    fn default_thresholds_match_contract() {
        let config = ScoreConfig::default();
        assert_eq!(config.warn_threshold, 15);
        assert_eq!(config.block_threshold, 100);
    }

    #[test]
    fn score_config_thresholds_are_used() {
        assert_eq!(
            score_reasons_with_config(
                &[reason(Severity::Medium)],
                ScoreConfig {
                    warn_threshold: 50,
                    block_threshold: 100,
                },
            ),
            (Decision::Allow, 15)
        );
    }
}
