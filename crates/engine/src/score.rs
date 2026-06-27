use crate::model::{Decision, Reason, Severity};
use serde::de::Error;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ScoreConfig {
    warn_threshold: u32,
    block_threshold: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScoreConfigError {
    pub warn_threshold: u32,
    pub block_threshold: u32,
}

impl ScoreConfig {
    pub fn new(warn_threshold: u32, block_threshold: u32) -> Result<Self, ScoreConfigError> {
        if warn_threshold < block_threshold {
            Ok(Self {
                warn_threshold,
                block_threshold,
            })
        } else {
            Err(ScoreConfigError {
                warn_threshold,
                block_threshold,
            })
        }
    }

    pub fn warn_threshold(self) -> u32 {
        self.warn_threshold
    }

    pub fn block_threshold(self) -> u32 {
        self.block_threshold
    }
}

impl Default for ScoreConfig {
    fn default() -> Self {
        Self {
            warn_threshold: 15,
            block_threshold: 100,
        }
    }
}

impl<'de> Deserialize<'de> for ScoreConfig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawScoreConfig {
            warn_threshold: u32,
            block_threshold: u32,
        }

        let raw = RawScoreConfig::deserialize(deserializer)?;
        ScoreConfig::new(raw.warn_threshold, raw.block_threshold).map_err(|error| {
            D::Error::custom(format!(
                "warn_threshold {} must be lower than block_threshold {}",
                error.warn_threshold, error.block_threshold
            ))
        })
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
        assert_eq!(config.warn_threshold(), 15);
        assert_eq!(config.block_threshold(), 100);
    }

    #[test]
    fn default_decision_boundaries_hold() {
        assert_eq!(score_reasons(&[]), (Decision::Allow, 0));
        assert_eq!(
            score_reasons(&[reason(Severity::Low)]),
            (Decision::Allow, 5)
        );
        assert_eq!(
            score_reasons(&[reason(Severity::Medium)]),
            (Decision::Warn, 15)
        );
        assert_eq!(
            score_reasons(&[
                reason(Severity::High),
                reason(Severity::High),
                reason(Severity::Medium),
                reason(Severity::Low),
            ]),
            (Decision::Block, 100)
        );
    }

    #[test]
    fn critical_always_blocks_with_custom_thresholds() {
        assert_eq!(
            score_reasons_with_config(
                &[reason(Severity::Critical)],
                ScoreConfig::new(15, 200).unwrap(),
            ),
            (Decision::Block, 100)
        );
    }

    #[test]
    fn score_config_thresholds_are_used() {
        assert_eq!(
            score_reasons_with_config(
                &[reason(Severity::Medium)],
                ScoreConfig::new(50, 100).unwrap(),
            ),
            (Decision::Allow, 15)
        );
    }

    #[test]
    fn score_config_rejects_inverted_thresholds() {
        assert_eq!(
            ScoreConfig::new(200, 100),
            Err(ScoreConfigError {
                warn_threshold: 200,
                block_threshold: 100,
            })
        );
    }

    #[test]
    fn score_config_deserialization_rejects_inverted_thresholds() {
        let result =
            serde_json::from_str::<ScoreConfig>(r#"{"warn_threshold":200,"block_threshold":100}"#);
        assert!(result.is_err());
    }
}
