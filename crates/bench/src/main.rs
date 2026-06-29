use aloo_engine::{Decision, Engine, HeuristicAnalyzer, load_package};
use std::path::{Path, PathBuf};
use std::process;

const RECALL_FLOOR: f64 = 0.80;
const FPR_CEILING: f64 = 0.10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Label {
    Benign,
    Malicious,
}

#[derive(Debug)]
struct FixtureResult {
    name: String,
    label: Label,
    decision: Decision,
}

#[derive(Debug, Default)]
struct ConfusionMatrix {
    true_positive: usize,
    false_positive: usize,
    true_negative: usize,
    false_negative: usize,
}

fn main() {
    if let Err(error) = run() {
        eprintln!("aloo-bench failed: {error}");
        process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let corpus_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("corpus");
    let engine = Engine::new(HeuristicAnalyzer);
    let mut results = Vec::new();

    for (label, directory) in [(Label::Benign, "benign"), (Label::Malicious, "malicious")] {
        let label_root = corpus_root.join(directory);
        let mut fixtures = collect_fixtures(&label_root)?;
        fixtures.sort();

        for fixture in fixtures {
            let package = load_package(&fixture)
                .map_err(|error| format!("failed to load {}: {error}", fixture.display()))?;
            let verdict = engine.evaluate_against(&package, None);
            results.push(FixtureResult {
                name: fixture
                    .strip_prefix(&corpus_root)
                    .unwrap_or(&fixture)
                    .to_string_lossy()
                    .replace('\\', "/"),
                label,
                decision: verdict.decision,
            });
        }
    }

    let matrix = confusion_matrix(&results);
    print_report(&results, &matrix);
    assert_gate(&matrix)?;
    Ok(())
}

fn collect_fixtures(root: &Path) -> Result<Vec<PathBuf>, String> {
    if !root.is_dir() {
        return Err(format!("missing corpus directory {}", root.display()));
    }

    let mut fixtures = Vec::new();
    for entry in std::fs::read_dir(root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let path = entry.path();
        if path.is_dir() && path.join("package.json").is_file() {
            fixtures.push(path);
        }
    }

    Ok(fixtures)
}

fn is_positive(decision: Decision) -> bool {
    decision != Decision::Allow
}

fn confusion_matrix(results: &[FixtureResult]) -> ConfusionMatrix {
    let mut matrix = ConfusionMatrix::default();

    for result in results {
        let positive = is_positive(result.decision);
        match (result.label, positive) {
            (Label::Malicious, true) => matrix.true_positive += 1,
            (Label::Malicious, false) => matrix.false_negative += 1,
            (Label::Benign, true) => matrix.false_positive += 1,
            (Label::Benign, false) => matrix.true_negative += 1,
        }
    }

    matrix
}

fn precision(matrix: &ConfusionMatrix) -> f64 {
    let positives = matrix.true_positive + matrix.false_positive;
    if positives == 0 {
        1.0
    } else {
        matrix.true_positive as f64 / positives as f64
    }
}

fn recall(matrix: &ConfusionMatrix) -> f64 {
    let actual_positives = matrix.true_positive + matrix.false_negative;
    if actual_positives == 0 {
        1.0
    } else {
        matrix.true_positive as f64 / actual_positives as f64
    }
}

fn false_positive_rate(matrix: &ConfusionMatrix) -> f64 {
    let actual_negatives = matrix.false_positive + matrix.true_negative;
    if actual_negatives == 0 {
        0.0
    } else {
        matrix.false_positive as f64 / actual_negatives as f64
    }
}

fn print_report(results: &[FixtureResult], matrix: &ConfusionMatrix) {
    println!("confusion matrix:");
    println!(
        "  TP={} FP={} FN={} TN={}",
        matrix.true_positive, matrix.false_positive, matrix.false_negative, matrix.true_negative
    );
    println!("precision={:.3}", precision(matrix));
    println!("recall={:.3}", recall(matrix));
    println!("false_positive_rate={:.3}", false_positive_rate(matrix));
    println!();

    for result in results {
        println!(
            "{} {:?} -> {:?}",
            result.name, result.label, result.decision
        );
    }
    println!();

    let false_negatives = results
        .iter()
        .filter(|result| result.label == Label::Malicious && !is_positive(result.decision))
        .map(|result| result.name.as_str())
        .collect::<Vec<_>>();
    let false_positives = results
        .iter()
        .filter(|result| result.label == Label::Benign && is_positive(result.decision))
        .map(|result| result.name.as_str())
        .collect::<Vec<_>>();

    if false_negatives.is_empty() {
        println!("false negatives: none");
    } else {
        println!("false negatives:");
        for name in false_negatives {
            println!("  {name}");
        }
    }

    if false_positives.is_empty() {
        println!("false positives: none");
    } else {
        println!("false positives:");
        for name in false_positives {
            println!("  {name}");
        }
    }
}

fn assert_gate(matrix: &ConfusionMatrix) -> Result<(), String> {
    let recall = recall(matrix);
    let fpr = false_positive_rate(matrix);

    if recall < RECALL_FLOOR {
        return Err(format!(
            "recall {:.3} is below floor {:.3}",
            recall, RECALL_FLOOR
        ));
    }

    if fpr > FPR_CEILING {
        return Err(format!(
            "false positive rate {:.3} exceeds ceiling {:.3}",
            fpr, FPR_CEILING
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn confusion_matrix_counts_predictions() {
        let results = vec![
            FixtureResult {
                name: "malicious/a".to_string(),
                label: Label::Malicious,
                decision: Decision::Warn,
            },
            FixtureResult {
                name: "malicious/b".to_string(),
                label: Label::Malicious,
                decision: Decision::Allow,
            },
            FixtureResult {
                name: "benign/a".to_string(),
                label: Label::Benign,
                decision: Decision::Allow,
            },
            FixtureResult {
                name: "benign/b".to_string(),
                label: Label::Benign,
                decision: Decision::Warn,
            },
        ];

        let matrix = confusion_matrix(&results);
        assert_eq!(matrix.true_positive, 1);
        assert_eq!(matrix.false_negative, 1);
        assert_eq!(matrix.true_negative, 1);
        assert_eq!(matrix.false_positive, 1);
        assert_eq!(recall(&matrix), 0.5);
        assert_eq!(false_positive_rate(&matrix), 0.5);
    }
}
