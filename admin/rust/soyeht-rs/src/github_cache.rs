//! On-disk TTL cache for GitHub API responses.
//!
//! Cache shape: one JSON file per (owner, repo, request kind) under
//! `/tmp/theyos-github-cache/`. Stored envelope is
//! `{ "stored_at": <epoch_secs>, "payload": <struct_json> }`.
//!
//! Callers pick a TTL (e.g. 1h for `claws-detect`, 5min for `claws-scan`).
//! When the file's `stored_at` is within the TTL, the payload is returned
//! directly; otherwise we fall through to the live client and refresh the
//! cache on success.

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::github_client::{FileContent, GitHubApi, GitHubError, Release, RepoMeta, Result};

/// Default cache root. Overridable for tests.
pub fn default_cache_dir() -> PathBuf {
    PathBuf::from("/tmp/theyos-github-cache")
}

#[derive(Serialize, Deserialize)]
struct Envelope<T> {
    stored_at: u64,
    payload: T,
}

fn cache_file(cache_dir: &Path, owner: &str, repo: &str, kind: &str) -> PathBuf {
    cache_dir.join(format!(
        "{}_{}__{kind}.json",
        sanitize(owner),
        sanitize(repo)
    ))
}

fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

fn read_cached<T: for<'de> Deserialize<'de>>(path: &Path, ttl: Duration) -> Option<T> {
    let content = std::fs::read_to_string(path).ok()?;
    let env: Envelope<T> = serde_json::from_str(&content).ok()?;
    let now = core_rs::time::unix_now_secs();
    if now.saturating_sub(env.stored_at) <= ttl.as_secs() {
        Some(env.payload)
    } else {
        None
    }
}

fn write_cached<T: Serialize>(path: &Path, payload: &T) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let env = Envelope {
        stored_at: core_rs::time::unix_now_secs(),
        payload,
    };
    let json = serde_json::to_string(&env).unwrap_or_else(|_| "{}".to_string());
    std::fs::write(path, json)
}

/// Fetch repo metadata through the cache.
///
/// # Errors
/// Bubbles up [`GitHubError`] from the underlying client on a cache miss.
pub fn cached_get_repo<C: GitHubApi>(
    client: &C,
    cache_dir: &Path,
    owner: &str,
    repo: &str,
    ttl: Duration,
) -> Result<RepoMeta> {
    let path = cache_file(cache_dir, owner, repo, "repo");
    if let Some(hit) = read_cached::<RepoMeta>(&path, ttl) {
        return Ok(hit);
    }
    let fresh = client.get_repo(owner, repo)?;
    let _ = write_cached(&path, &fresh);
    Ok(fresh)
}

/// Fetch latest release through the cache. `None` is a legitimate cached value
/// (e.g. repos without any release).
///
/// # Errors
/// Bubbles up [`GitHubError`] from the underlying client on a cache miss.
pub fn cached_latest_release<C: GitHubApi>(
    client: &C,
    cache_dir: &Path,
    owner: &str,
    repo: &str,
    ttl: Duration,
) -> Result<Option<Release>> {
    let path = cache_file(cache_dir, owner, repo, "release");
    if let Some(hit) = read_cached::<Option<Release>>(&path, ttl) {
        return Ok(hit);
    }
    let fresh = client.latest_release(owner, repo)?;
    let _ = write_cached(&path, &fresh);
    Ok(fresh)
}

/// Fetch file contents through the cache.
///
/// # Errors
/// Bubbles up [`GitHubError`] from the underlying client on a cache miss.
pub fn cached_get_contents<C: GitHubApi>(
    client: &C,
    cache_dir: &Path,
    owner: &str,
    repo: &str,
    file_path: &str,
    ttl: Duration,
) -> Result<Option<FileContent>> {
    let kind = format!("contents_{}", sanitize(file_path));
    let path = cache_file(cache_dir, owner, repo, &kind);
    if let Some(hit) = read_cached::<Option<FileContent>>(&path, ttl) {
        return Ok(hit);
    }
    let fresh = client.get_contents(owner, repo, file_path)?;
    let _ = write_cached(&path, &fresh);
    Ok(fresh)
}

/// Fetch a branch HEAD SHA through the cache.
///
/// # Errors
/// Bubbles up [`GitHubError`] from the underlying client on a cache miss.
pub fn cached_head_sha<C: GitHubApi>(
    client: &C,
    cache_dir: &Path,
    owner: &str,
    repo: &str,
    branch: Option<&str>,
    ttl: Duration,
) -> Result<String> {
    let kind = match branch {
        Some(b) => format!("head_{}", sanitize(b)),
        None => "head_default".to_string(),
    };
    let path = cache_file(cache_dir, owner, repo, &kind);
    if let Some(hit) = read_cached::<String>(&path, ttl) {
        return Ok(hit);
    }
    let fresh = client.head_sha(owner, repo, branch)?;
    let _ = write_cached(&path, &fresh);
    Ok(fresh)
}

// Silence the unused-import warning when this symbol is only referenced via
// error types in callers.
#[allow(dead_code)]
fn _ensure_error_is_imported() -> Option<GitHubError> {
    None
}

// ── Tests (offline) ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github_client::Asset;
    use std::cell::RefCell;

    /// Mock that counts how many times each method was invoked.
    struct MockApi {
        repo_calls: RefCell<u32>,
        release_calls: RefCell<u32>,
        contents_calls: RefCell<u32>,
        head_calls: RefCell<u32>,
        release: Option<Release>,
    }

    impl MockApi {
        fn new() -> Self {
            Self {
                repo_calls: RefCell::new(0),
                release_calls: RefCell::new(0),
                contents_calls: RefCell::new(0),
                head_calls: RefCell::new(0),
                release: Some(Release {
                    tag_name: "v1".into(),
                    assets: vec![Asset {
                        name: "foo-linux-amd64.tar.gz".into(),
                        browser_download_url: "https://example/d".into(),
                        size: 1,
                    }],
                    published_at: "2026-04-01T00:00:00Z".into(),
                }),
            }
        }
    }

    impl GitHubApi for MockApi {
        fn get_repo(&self, _owner: &str, _repo: &str) -> Result<RepoMeta> {
            *self.repo_calls.borrow_mut() += 1;
            Ok(RepoMeta {
                name: "x".into(),
                stars: 1,
                pushed_at: "2026-04-10T00:00:00Z".into(),
                license_spdx: "MIT".into(),
                default_branch: "main".into(),
                html_url: "https://github.com/o/x".into(),
                description: "d".into(),
            })
        }
        fn latest_release(&self, _owner: &str, _repo: &str) -> Result<Option<Release>> {
            *self.release_calls.borrow_mut() += 1;
            Ok(self.release.clone())
        }
        fn get_contents(
            &self,
            _owner: &str,
            _repo: &str,
            path: &str,
        ) -> Result<Option<FileContent>> {
            *self.contents_calls.borrow_mut() += 1;
            Ok(Some(FileContent {
                path: path.to_string(),
                content: format!("content-of-{path}"),
            }))
        }
        fn head_sha(&self, _owner: &str, _repo: &str, _branch: Option<&str>) -> Result<String> {
            *self.head_calls.borrow_mut() += 1;
            Ok("deadbeef".into())
        }
    }

    #[test]
    fn cache_hits_second_call_under_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockApi::new();
        let _ = cached_get_repo(&mock, tmp.path(), "o", "x", Duration::from_secs(3600)).unwrap();
        let _ = cached_get_repo(&mock, tmp.path(), "o", "x", Duration::from_secs(3600)).unwrap();
        assert_eq!(*mock.repo_calls.borrow(), 1);
    }

    #[test]
    fn cache_misses_when_ttl_zero() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockApi::new();
        let _ = cached_get_repo(&mock, tmp.path(), "o", "x", Duration::from_secs(0)).unwrap();
        // Sleep 1 second to ensure stored_at < now.
        std::thread::sleep(Duration::from_millis(1100));
        let _ = cached_get_repo(&mock, tmp.path(), "o", "x", Duration::from_secs(0)).unwrap();
        assert_eq!(*mock.repo_calls.borrow(), 2);
    }

    #[test]
    fn cache_contents_keyed_by_path() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockApi::new();
        let _ = cached_get_contents(
            &mock,
            tmp.path(),
            "o",
            "x",
            "Cargo.toml",
            Duration::from_secs(3600),
        )
        .unwrap();
        let _ = cached_get_contents(
            &mock,
            tmp.path(),
            "o",
            "x",
            "go.mod",
            Duration::from_secs(3600),
        )
        .unwrap();
        assert_eq!(*mock.contents_calls.borrow(), 2);
        // Re-fetching Cargo.toml is a cache hit.
        let _ = cached_get_contents(
            &mock,
            tmp.path(),
            "o",
            "x",
            "Cargo.toml",
            Duration::from_secs(3600),
        )
        .unwrap();
        assert_eq!(*mock.contents_calls.borrow(), 2);
    }

    #[test]
    fn cache_head_sha_honours_ttl() {
        let tmp = tempfile::tempdir().unwrap();
        let mock = MockApi::new();
        let _ =
            cached_head_sha(&mock, tmp.path(), "o", "x", None, Duration::from_secs(3600)).unwrap();
        let _ =
            cached_head_sha(&mock, tmp.path(), "o", "x", None, Duration::from_secs(3600)).unwrap();
        assert_eq!(*mock.head_calls.borrow(), 1);
    }

    #[test]
    fn cache_release_caches_none() {
        let tmp = tempfile::tempdir().unwrap();
        let mut mock = MockApi::new();
        mock.release = None;
        let r1 =
            cached_latest_release(&mock, tmp.path(), "o", "x", Duration::from_secs(3600)).unwrap();
        let r2 =
            cached_latest_release(&mock, tmp.path(), "o", "x", Duration::from_secs(3600)).unwrap();
        assert!(r1.is_none() && r2.is_none());
        assert_eq!(*mock.release_calls.borrow(), 1);
    }

    #[test]
    fn sanitize_replaces_path_separators() {
        assert_eq!(sanitize("foo/bar"), "foo_bar");
        assert_eq!(sanitize("a.b-c_d"), "a.b-c_d");
    }
}
