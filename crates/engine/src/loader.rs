use crate::model::{CODE_EXTENSIONS, MAX_FILE_BYTES, Manifest, PackageVersion, SourceFile};
use flate2::read::GzDecoder;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read};
use std::path::{Component, Path, PathBuf};
use tar::Archive;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum LoadError {
    #[error("io error: {0}")]
    Io(#[from] io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("missing package.json at {0}")]
    MissingManifest(String),
    #[error("unsupported package path: {0}")]
    UnsupportedPath(String),
}

pub fn load_package(path: &Path) -> Result<PackageVersion, LoadError> {
    if path.extension().and_then(|value| value.to_str()) == Some("tgz") {
        load_tarball(path)
    } else if path.is_dir() {
        load_dir(path)
    } else {
        Err(LoadError::UnsupportedPath(path.display().to_string()))
    }
}

pub fn load_dir(path: &Path) -> Result<PackageVersion, LoadError> {
    let manifest_path = path.join("package.json");
    if !manifest_path.is_file() {
        return Err(LoadError::MissingManifest(
            manifest_path.display().to_string(),
        ));
    }

    let raw = fs::read_to_string(&manifest_path)?;
    let manifest = parse_manifest(raw)?;
    let mut files = Vec::new();
    collect_dir_files(path, path, &mut files)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(PackageVersion {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        manifest,
        files,
    })
}

pub fn load_tarball(path: &Path) -> Result<PackageVersion, LoadError> {
    let file = File::open(path)?;
    load_tarball_reader(file)
}

fn load_tarball_reader<R: Read>(reader: R) -> Result<PackageVersion, LoadError> {
    let decoder = GzDecoder::new(reader);
    let mut archive = Archive::new(decoder);
    let mut manifest_raw = None;
    let mut files = Vec::new();

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?.into_owned();
        let relative = tarball_entry_path(&path)?;
        if relative.as_os_str().is_empty() {
            continue;
        }

        let relative_path = relative.to_string_lossy().replace('\\', "/");
        if relative_path == "package.json" {
            let mut raw = String::new();
            entry.read_to_string(&mut raw)?;
            manifest_raw = Some(raw);
            continue;
        }

        if !is_code_path(&relative) {
            continue;
        }

        if entry.size() > MAX_FILE_BYTES as u64 {
            continue;
        }

        let mut contents = String::new();
        entry.read_to_string(&mut contents)?;
        files.push(SourceFile {
            path: relative_path,
            contents,
        });
    }

    let raw = manifest_raw.ok_or_else(|| LoadError::MissingManifest("package.json".to_string()))?;
    let manifest = parse_manifest(raw)?;
    files.sort_by(|left, right| left.path.cmp(&right.path));

    Ok(PackageVersion {
        name: manifest.name.clone(),
        version: manifest.version.clone(),
        manifest,
        files,
    })
}

fn parse_manifest(raw: String) -> Result<Manifest, LoadError> {
    let parsed: PackageJson = serde_json::from_str(&raw)?;
    Ok(Manifest {
        name: parsed.name,
        version: parsed.version,
        scripts: parsed.scripts,
        raw,
    })
}

#[derive(Deserialize)]
struct PackageJson {
    name: String,
    version: String,
    #[serde(default)]
    scripts: BTreeMap<String, String>,
}

fn collect_dir_files(
    root: &Path,
    current: &Path,
    files: &mut Vec<SourceFile>,
) -> Result<(), LoadError> {
    for entry in fs::read_dir(current)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        if name == "node_modules" {
            continue;
        }

        let path = entry.path();
        if path.is_dir() {
            collect_dir_files(root, &path, files)?;
            continue;
        }

        if !is_code_path(&path) {
            continue;
        }

        let metadata = fs::metadata(&path)?;
        if metadata.len() as usize > MAX_FILE_BYTES {
            continue;
        }

        let relative = path
            .strip_prefix(root)
            .map_err(|_| LoadError::UnsupportedPath(path.display().to_string()))?;
        let relative_path = relative.to_string_lossy().replace('\\', "/");
        let contents = fs::read_to_string(&path)?;
        files.push(SourceFile {
            path: relative_path,
            contents,
        });
    }

    Ok(())
}

fn is_code_path(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|extension| CODE_EXTENSIONS.contains(&extension))
}

fn tarball_entry_path(path: &Path) -> Result<PathBuf, LoadError> {
    let mut components = path
        .components()
        .filter(|component| !matches!(component, Component::CurDir | Component::RootDir))
        .peekable();

    if components.peek().is_some_and(|component| {
        matches!(component, Component::Normal(value) if value.to_string_lossy() == "package")
    }) {
        components.next();
    }

    Ok(components.collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn corpus_fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../bench/corpus")
            .join(name)
    }

    #[test]
    fn load_dir_reads_manifest_and_code_files() {
        let package = load_dir(&corpus_fixture("benign/legitimate-fetch")).unwrap();

        assert_eq!(package.name, "legitimate-fetch");
        assert_eq!(package.version, "1.0.0");
        assert!(package.files.iter().any(|file| file.path == "index.js"));
    }

    #[test]
    fn load_package_dispatches_to_directory_loader() {
        let package = load_package(&corpus_fixture("malicious/env-to-fetch")).unwrap();

        assert_eq!(package.name, "env-to-fetch");
        assert!(package.files.iter().any(|file| file.path == "index.js"));
    }

    #[test]
    fn load_tarball_matches_directory_fixture() -> Result<(), Box<dyn std::error::Error>> {
        use flate2::Compression;
        use flate2::write::GzEncoder;
        use tar::Builder;

        let fixture_dir = corpus_fixture("benign/readable-strings");
        let tarball_path =
            std::env::temp_dir().join(format!("aloo-loader-{}.tgz", std::process::id()));
        let file = File::create(&tarball_path)?;
        let encoder = GzEncoder::new(file, Compression::default());
        let mut builder = Builder::new(encoder);
        builder.append_path_with_name(fixture_dir.join("package.json"), "package/package.json")?;
        builder.append_path_with_name(fixture_dir.join("index.js"), "package/index.js")?;
        let encoder = builder.into_inner()?;
        encoder.finish()?;

        let dir_package = load_dir(&fixture_dir)?;
        let tarball_package = load_tarball(&tarball_path)?;

        assert_eq!(dir_package.name, tarball_package.name);
        assert_eq!(dir_package.version, tarball_package.version);
        assert_eq!(
            dir_package.manifest.scripts,
            tarball_package.manifest.scripts
        );
        assert_eq!(dir_package.files, tarball_package.files);

        let _ = fs::remove_file(tarball_path);
        Ok(())
    }

    #[test]
    fn load_dir_skips_node_modules() -> Result<(), Box<dyn std::error::Error>> {
        let temp = std::env::temp_dir().join(format!("aloo-loader-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir_all(temp.join("node_modules/nested"))?;
        fs::write(
            temp.join("package.json"),
            r#"{"name":"case","version":"1.0.0","scripts":{}}"#,
        )?;
        fs::write(temp.join("index.js"), "fetch('https://example.com');")?;
        fs::write(
            temp.join("node_modules/nested/index.js"),
            "process.env.SECRET;",
        )?;

        let package = load_dir(&temp)?;
        assert_eq!(package.files.len(), 1);
        assert_eq!(package.files[0].path, "index.js");

        let _ = fs::remove_dir_all(temp);
        Ok(())
    }

    #[test]
    fn load_dir_skips_oversized_files() -> Result<(), Box<dyn std::error::Error>> {
        let temp = std::env::temp_dir().join(format!("aloo-loader-large-{}", std::process::id()));
        let _ = fs::remove_dir_all(&temp);
        fs::create_dir(&temp)?;
        fs::write(
            temp.join("package.json"),
            r#"{"name":"case","version":"1.0.0","scripts":{}}"#,
        )?;
        let mut large = File::create(temp.join("large.js"))?;
        let payload = vec![b'a'; MAX_FILE_BYTES + 1];
        large.write_all(&payload)?;

        let package = load_dir(&temp)?;
        assert!(package.files.is_empty());

        let _ = fs::remove_dir_all(temp);
        Ok(())
    }
}
