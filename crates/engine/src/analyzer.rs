use crate::model::{PackageFacts, PackageVersion};

pub trait Analyzer {
    fn name(&self) -> &str;
    fn analyze_package(&self, pkg: &PackageVersion) -> PackageFacts;
}
