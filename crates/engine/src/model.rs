use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_FILE_BYTES: usize = 2 * 1024 * 1024;
pub const CODE_EXTENSIONS: &[&str] = &["js", "cjs", "mjs", "ts", "jsx", "tsx"];
pub const LIFECYCLE_HOOKS: &[&str] = &["preinstall", "install", "postinstall"];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub name: String,
    pub version: String,
    pub scripts: BTreeMap<String, String>,
    pub raw: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceFile {
    pub path: String,
    pub contents: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageVersion {
    pub name: String,
    pub version: String,
    pub manifest: Manifest,
    pub files: Vec<SourceFile>,
}

impl PackageVersion {
    pub fn lifecycle_scripts(&self) -> impl Iterator<Item = (&str, &str)> {
        LIFECYCLE_HOOKS.iter().filter_map(|hook| {
            self.manifest
                .scripts
                .get(*hook)
                .map(|body| (*hook, body.as_str()))
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sensitivity {
    Elevated,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    ProcessEnv,
    EnvFile,
    NpmToken,
    SshKey,
    AwsCredentials,
    WalletData,
    BrowserData,
}

impl SourceKind {
    pub fn sensitivity(self) -> Sensitivity {
        match self {
            SourceKind::ProcessEnv | SourceKind::EnvFile | SourceKind::BrowserData => {
                Sensitivity::Elevated
            }
            SourceKind::NpmToken
            | SourceKind::SshKey
            | SourceKind::AwsCredentials
            | SourceKind::WalletData => Sensitivity::Critical,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            SourceKind::ProcessEnv => "environment variable",
            SourceKind::EnvFile => ".env file",
            SourceKind::NpmToken => "npm auth token",
            SourceKind::SshKey => "SSH key",
            SourceKind::AwsCredentials => "AWS credential",
            SourceKind::WalletData => "wallet data",
            SourceKind::BrowserData => "browser data",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkKind {
    NetworkSend,
    ProcessExec,
    DynamicEval,
    FilesystemWrite,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Evidence {
    pub file: String,
    pub line: usize,
    pub snippet: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SourceObs {
    pub kind: SourceKind,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SinkObs {
    pub kind: SinkKind,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct FlowObs {
    pub source: SourceKind,
    pub sink: SinkKind,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileFacts {
    pub path: String,
    pub sources: Vec<SourceObs>,
    pub sinks: Vec<SinkObs>,
    pub flows: Vec<FlowObs>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageFacts {
    pub files: Vec<FileFacts>,
}

impl PackageFacts {
    pub fn flows(&self) -> impl Iterator<Item = &FlowObs> {
        self.files.iter().flat_map(|file| file.flows.iter())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Warn,
    Block,
}

impl Decision {
    pub fn exit_code(self) -> i32 {
        match self {
            Decision::Allow => 0,
            Decision::Warn => 1,
            Decision::Block => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReasonCode {
    InstallScriptPresent,
    DangerousInstallScript,
    Obfuscation,
    DynamicEval,
    KnownIoc,
    CredentialExfiltration,
    RiskIntroducedInRelease,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Reason {
    pub code: ReasonCode,
    pub severity: Severity,
    pub title: String,
    pub detail: String,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Verdict {
    pub package: String,
    pub version: String,
    pub decision: Decision,
    pub score: u32,
    pub analyzer: String,
    pub reasons: Vec<Reason>,
}

pub fn evidence(file: impl Into<String>, line: usize, snippet: impl AsRef<str>) -> Evidence {
    let mut text = snippet.as_ref().trim().replace('\t', " ");
    while text.contains("  ") {
        text = text.replace("  ", " ");
    }
    if text.len() > 160 {
        text.truncate(157);
        text.push_str("...");
    }
    Evidence {
        file: file.into(),
        line,
        snippet: text,
    }
}
