use crate::analyzer::Analyzer;
use crate::model::{PackageFacts, PackageVersion};

pub struct OxcAnalyzer;

impl Analyzer for OxcAnalyzer {
    fn name(&self) -> &str {
        "oxc"
    }

    fn analyze_package(&self, pkg: &PackageVersion) -> PackageFacts {
        crate::backend::heuristic::HeuristicAnalyzer.analyze_package(pkg)
    }
}
