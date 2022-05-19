//! # GitHub import resolver
//!
//! GitHub import resolver allows to import files located in github.com repos.
//!
//! To import file from github, use following syntax:
//! ```zokrates
//! import "github:user/repo/branch/path/to/file.code"
//! ```
//!
//! For example:
//! ```zokrates
//! import "github.com/Zokrates/ZoKrates/master/zokrates_cli/examples/merkleTree/sha256PathProof3.code" as merkleTreeProof
//! ```
//!
//! Example above imports file `zokrates_cli/examples/merkleTree/sha256PathProof3.code` located at ZoKrates
//! repository's `master` branch by downloading from URL:
//! https://raw.githubusercontent.com/Zokrates/ZoKrates/master/zokrates_cli/examples/merkleTree/sha256PathProof3.code
//!

use reqwest;
use std::fs::File;
use std::io::{self, copy, BufReader};
use std::path::{Path, PathBuf};
use tempfile::NamedTempFile;

#[cfg(test)]
use mockito::{self, Mock};

/// Prefix for github import source to be distinguished.
const GITHUB_IMPORT_PREFIX: &str = "github.com/";

/// GitHub download URL base
#[cfg(not(test))]
const GITHUB_URL_BASE: &str = "https://raw.githubusercontent.com";

/// Resolves import from the Github.
/// This importer needs to be provided with location since relative paths could be used inside the
/// files that are imported from github.
pub fn resolve<'a>(
    location: Option<String>,
    path: &'a str,
) -> Result<(BufReader<File>, String, &'a str), io::Error> {
    if let Some(location) = location {
        let path = Path::new(path);
        let (root, repo, branch, file_path) = parse_input_path(&path)?;

        #[cfg(not(test))]
        let url = GITHUB_URL_BASE;
        #[cfg(test)]
        let url = mockito::server_url();

        let pb = download_from_github(&url, &root, &repo, &branch, &file_path)?;
        let file = File::open(&pb)?;
        let br = BufReader::new(file);

        let alias = path.file_stem().unwrap().to_str().unwrap();

        Ok((br, location.to_owned(), &alias))
    } else {
        Err(io::Error::new(io::ErrorKind::Other, "No location provided"))
    }
}

/// Checks that import source is using github import location.
pub fn is_github_import(source: &str) -> bool {
    source.starts_with(GITHUB_IMPORT_PREFIX)
}

/// Parses github import syntax: "github.com/<root>/<repo>/<branch>/<path/to/file>"
/// Where:
/// - <root> is the user or organization name
/// - <repo> is the repository name
/// - <branch> is the branch/snapshot name, e.g. `master`
/// - <path/to/file> is the absolute path to file in the specified branch of the repository
fn parse_input_path<'a>(path: &'a Path) -> Result<(&'a str, &'a str, &'a str, &'a str), io::Error> {
    //let path_owned = path.replacen(GITHUB_IMPORT_PREFIX, "", 1);
    if path.to_str().unwrap().contains("..") {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid github import syntax. It must not contain '..'",
        ));
    }

    let mut components = path.components();

    // Check that root, repo, branch & path are specified
    if components.clone().count() < 5 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!(
                "Invalid github import syntax. Should be: {}<root>/<repo>/<branch>/<path>",
                GITHUB_IMPORT_PREFIX
            ),
        ));
    }

    let _ = components.next().unwrap().as_os_str().to_str().unwrap();
    let root = components.next().unwrap().as_os_str().to_str().unwrap();
    let repo = components.next().unwrap().as_os_str().to_str().unwrap();
    let branch = components.next().unwrap().as_os_str().to_str().unwrap();
    let path = components.as_path().to_str().unwrap(); // Collect the rest of the import path into single string

    Ok((root, repo, branch, path))
}

/// Downloads the file from github by specific root (user/org), repository, branch and path.
fn download_from_github(
    github: &str,
    root: &str,
    repo: &str,
    branch: &str,
    path: &str,
) -> Result<PathBuf, io::Error> {
    let url = format!(
        "{github}/{root}/{repo}/{branch}/{path}",
        github = github,
        root = root,
        repo = repo,
        branch = branch,
        path = path
    );

    download_url(&url)
}

fn download_url(url: &str) -> Result<PathBuf, io::Error> {
    let mut response = reqwest::get(url).map_err(|e| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("Unable to access github: {}", e.to_string()),
        )
    })?;

    if !response.status().is_success() {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            format!("Unable to access github: {}", response.status()),
        ));
    }

    let (mut dest, pb) = NamedTempFile::new()?.keep()?;
    copy(&mut response, &mut dest)?;

    Ok(pb)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Initializes github.com mocks for `import_github` example to run from `examples` tests.
    /// Note that returned mock objects should be alive prior to github requests.
    fn init_github_mock() -> (Mock, Mock) {
        let m1 = mockito::mock(
            "GET",
            "/Zokrates/ZoKrates/master/zokrates_cli/examples/imports/foo.code",
        )
        .with_status(200)
        .with_body_from_file("./static/foo.code")
        .create();

        let m2 = mockito::mock(
            "GET",
            "/Zokrates/ZoKrates/master/zokrates_cli/examples/imports/notfound.code",
        )
        .with_status(404)
        .create();

        (m1, m2)
    }

    #[test]
    pub fn import_simple() {
        let res = parse_input_path(Path::new(
            "github.com/Zokrates/ZoKrates/master/zokrates_cli/examples/imports/import.code",
        ))
        .unwrap();
        let (root, repo, branch, path) = res;

        assert_eq!(root, "Zokrates");
        assert_eq!(repo, "ZoKrates");
        assert_eq!(branch, "master");
        assert_eq!(path, "zokrates_cli/examples/imports/import.code");
    }

    #[test]
    #[should_panic]
    pub fn import_no_branch() {
        // Correct syntax should be: github.com/Zokrates/ZoKrates/master/zokrates_cli/examples/imports/import.code
        // but branch name is not specified
        parse_input_path(Path::new("github.com/Zokrates/ZoKrates/test.code")).unwrap();
    }

    #[test]
    #[should_panic]
    pub fn import_relative_paths() {
        // Relative paths should not be allowed
        parse_input_path(Path::new(
            "github.com/Zokrates/ZoKrates/master/examples/../imports.code",
        ))
        .unwrap();
    }

    #[test]
    pub fn resolve_ok() {
        let (_m0, _m1) = init_github_mock();
        let res = resolve(
            Some("".to_string()),
            &"github.com/Zokrates/ZoKrates/master/zokrates_cli/examples/imports/foo.code",
        );
        assert!(res.is_ok());
    }

    #[test]
    pub fn resolve_err() {
        let (_m0, _m1) = init_github_mock();
        assert!(resolve(
            Some("".to_string()),
            &"github.com/Zokrates/ZoKrates/master/zokrates_cli/examples/imports/notfound.code"
        )
        .is_err());
    }
}
