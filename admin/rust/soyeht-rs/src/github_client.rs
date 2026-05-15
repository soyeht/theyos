//! Thin wrapper over the GitHub REST API for the claws detector.
//!
//! Uses blocking `ureq` to stay consistent with the rest of `soyeht-rs`.
//! All network I/O lives here; higher layers (`detector`, `claws_detect`,
//! `claws_scan`) depend on the [`GitHubApi`] trait so they can be unit-tested
//! without touching the network.

use std::time::Duration;

use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// Metadata for a GitHub repository.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RepoMeta {
    pub name: String,
    pub stars: u64,
    pub pushed_at: String,
    pub license_spdx: String,
    pub default_branch: String,
    pub html_url: String,
    pub description: String,
}

/// A GitHub release plus its assets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Release {
    pub tag_name: String,
    pub assets: Vec<Asset>,
    pub published_at: String,
}

/// One release asset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Asset {
    pub name: String,
    pub browser_download_url: String,
    pub size: u64,
}

/// Contents of a file fetched via the contents API.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileContent {
    pub path: String,
    /// UTF-8 body (already base64-decoded).
    pub content: String,
}

/// Error type produced by the client.
#[derive(Debug)]
pub enum GitHubError {
    /// Network / transport failure.
    Transport(String),
    /// Non-2xx, non-404 HTTP status.
    Http { status: u16, body: String },
    /// JSON parse / base64 decode failure.
    Parse(String),
    /// Missing or malformed input (e.g. non-GitHub URL).
    BadInput(String),
}

impl std::fmt::Display for GitHubError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "github transport error: {e}"),
            Self::Http { status, body } => {
                let snippet: String = body.chars().take(200).collect();
                write!(f, "github http {status}: {snippet}")
            }
            Self::Parse(e) => write!(f, "github parse error: {e}"),
            Self::BadInput(e) => write!(f, "github bad input: {e}"),
        }
    }
}

impl std::error::Error for GitHubError {}

pub type Result<T> = std::result::Result<T, GitHubError>;

/// Abstract GitHub API — lets tests substitute a mock.
pub trait GitHubApi {
    fn get_repo(&self, owner: &str, repo: &str) -> Result<RepoMeta>;
    fn latest_release(&self, owner: &str, repo: &str) -> Result<Option<Release>>;
    fn get_contents(&self, owner: &str, repo: &str, path: &str) -> Result<Option<FileContent>>;
    fn head_sha(&self, owner: &str, repo: &str, branch: Option<&str>) -> Result<String>;
}

/// Live client against api.github.com.
pub struct GitHubClient {
    agent: ureq::Agent,
    token: Option<String>,
    /// Delay between outgoing requests to soothe the secondary rate limit.
    inter_request_delay: Duration,
    last_request: std::sync::Mutex<Option<std::time::Instant>>,
}

impl Default for GitHubClient {
    fn default() -> Self {
        Self::new()
    }
}

impl GitHubClient {
    /// Build a client, picking up `GITHUB_TOKEN` from the environment.
    #[must_use]
    pub fn new() -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(Duration::from_secs(30))
            .build();
        let token = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty());
        Self {
            agent,
            token,
            inter_request_delay: Duration::from_millis(100),
            last_request: std::sync::Mutex::new(None),
        }
    }

    /// True if `GITHUB_TOKEN` was found in the environment.
    #[must_use]
    pub fn has_token(&self) -> bool {
        self.token.is_some()
    }

    fn sleep_if_needed(&self) {
        let mut guard = self
            .last_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(last) = *guard {
            let elapsed = last.elapsed();
            if let Some(remaining) = self.inter_request_delay.checked_sub(elapsed) {
                if !remaining.is_zero() {
                    std::thread::sleep(remaining);
                }
            }
        }
        *guard = Some(std::time::Instant::now());
    }

    fn build_request(&self, url: &str) -> ureq::Request {
        let mut req = self
            .agent
            .get(url)
            .set("User-Agent", "theyos-claws-detector")
            .set("Accept", "application/vnd.github+json")
            .set("X-GitHub-Api-Version", "2022-11-28");
        if let Some(ref t) = self.token {
            req = req.set("Authorization", &format!("Bearer {t}"));
        }
        req
    }

    fn call_json(&self, url: &str) -> Result<Option<serde_json::Value>> {
        self.sleep_if_needed();
        let req = self.build_request(url);
        match req.call() {
            Ok(resp) => {
                let body = resp
                    .into_string()
                    .map_err(|e| GitHubError::Transport(e.to_string()))?;
                let v: serde_json::Value =
                    serde_json::from_str(&body).map_err(|e| GitHubError::Parse(e.to_string()))?;
                Ok(Some(v))
            }
            Err(ureq::Error::Status(404, _)) => Ok(None),
            Err(ureq::Error::Status(status, resp)) => {
                let body = resp.into_string().unwrap_or_default();
                Err(GitHubError::Http { status, body })
            }
            Err(e) => Err(GitHubError::Transport(e.to_string())),
        }
    }
}

impl GitHubApi for GitHubClient {
    fn get_repo(&self, owner: &str, repo: &str) -> Result<RepoMeta> {
        let url = format!("https://api.github.com/repos/{owner}/{repo}");
        let v = self
            .call_json(&url)?
            .ok_or_else(|| GitHubError::BadInput(format!("repo not found: {owner}/{repo}")))?;
        Ok(parse_repo_meta(&v))
    }

    fn latest_release(&self, owner: &str, repo: &str) -> Result<Option<Release>> {
        let url = format!("https://api.github.com/repos/{owner}/{repo}/releases/latest");
        let Some(v) = self.call_json(&url)? else {
            return Ok(None);
        };
        Ok(Some(parse_release(&v)))
    }

    fn get_contents(&self, owner: &str, repo: &str, path: &str) -> Result<Option<FileContent>> {
        let url = format!("https://api.github.com/repos/{owner}/{repo}/contents/{path}");
        let Some(v) = self.call_json(&url)? else {
            return Ok(None);
        };
        parse_file_content(path, &v).map(Some)
    }

    fn head_sha(&self, owner: &str, repo: &str, branch: Option<&str>) -> Result<String> {
        // Resolve the branch (default branch when None).
        let resolved_branch = if let Some(b) = branch {
            b.to_string()
        } else {
            self.get_repo(owner, repo)?.default_branch
        };
        let url = format!("https://api.github.com/repos/{owner}/{repo}/commits/{resolved_branch}");
        let v = self
            .call_json(&url)?
            .ok_or_else(|| GitHubError::BadInput(format!("branch not found: {resolved_branch}")))?;
        v.get("sha")
            .and_then(|s| s.as_str())
            .map(std::string::ToString::to_string)
            .ok_or_else(|| GitHubError::Parse("commits payload missing `sha`".into()))
    }
}

// ── JSON parsers (pure — unit testable) ─────────────────────────────────────

fn parse_repo_meta(v: &serde_json::Value) -> RepoMeta {
    let license_spdx = v
        .get("license")
        .and_then(|l| l.get("spdx_id"))
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string();
    RepoMeta {
        name: string_field(v, "name"),
        stars: v
            .get("stargazers_count")
            .and_then(serde_json::Value::as_u64)
            .unwrap_or(0),
        pushed_at: string_field(v, "pushed_at"),
        license_spdx,
        default_branch: string_field_default(v, "default_branch", "main"),
        html_url: string_field(v, "html_url"),
        description: string_field(v, "description"),
    }
}

fn parse_release(v: &serde_json::Value) -> Release {
    let assets: Vec<Asset> = v
        .get("assets")
        .and_then(|a| a.as_array())
        .map(|arr| {
            arr.iter()
                .map(|a| Asset {
                    name: string_field(a, "name"),
                    browser_download_url: string_field(a, "browser_download_url"),
                    size: a
                        .get("size")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default();
    Release {
        tag_name: string_field(v, "tag_name"),
        assets,
        published_at: string_field(v, "published_at"),
    }
}

fn parse_file_content(path: &str, v: &serde_json::Value) -> Result<FileContent> {
    let encoding = v.get("encoding").and_then(|e| e.as_str()).unwrap_or("");
    let raw = v.get("content").and_then(|c| c.as_str()).unwrap_or("");
    let decoded = if encoding == "base64" {
        // GitHub base64 content may contain newlines — strip them before decoding.
        let cleaned: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(cleaned.as_bytes())
            .map_err(|e| GitHubError::Parse(format!("base64 decode failed: {e}")))?;
        String::from_utf8_lossy(&bytes).into_owned()
    } else {
        raw.to_string()
    };
    Ok(FileContent {
        path: path.to_string(),
        content: decoded,
    })
}

fn string_field(v: &serde_json::Value, key: &str) -> String {
    v.get(key)
        .and_then(|s| s.as_str())
        .unwrap_or("")
        .to_string()
}

fn string_field_default(v: &serde_json::Value, key: &str, default: &str) -> String {
    v.get(key)
        .and_then(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .unwrap_or(default)
        .to_string()
}

/// Parse a `https://github.com/owner/repo[.git][/]` URL into `(owner, repo)`.
///
/// # Errors
///
/// Returns an error if the URL is not a GitHub URL or is missing `owner/repo`.
pub fn parse_repo_url(url: &str) -> Result<(String, String)> {
    let trimmed = url.trim();
    // Strip scheme
    let no_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .or_else(|| trimmed.strip_prefix("git@"))
        .unwrap_or(trimmed);
    // Normalise `git@github.com:owner/repo` form to `github.com/owner/repo`.
    let normalised = no_scheme.replacen(':', "/", 1);
    let without_host = normalised
        .strip_prefix("github.com/")
        .or_else(|| normalised.strip_prefix("www.github.com/"))
        .ok_or_else(|| GitHubError::BadInput(format!("not a GitHub URL: {url}")))?;
    let cleaned = without_host.trim_end_matches('/').trim_end_matches(".git");
    let mut parts = cleaned.splitn(3, '/');
    let owner = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| GitHubError::BadInput(format!("missing owner: {url}")))?;
    let repo = parts
        .next()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| GitHubError::BadInput(format!("missing repo: {url}")))?;
    Ok((owner.to_string(), repo.to_string()))
}

// ── Tests (offline — no network) ────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_repo_url_https() {
        let (o, r) = parse_repo_url("https://github.com/sipeed/picoclaw").unwrap();
        assert_eq!(o, "sipeed");
        assert_eq!(r, "picoclaw");
    }

    #[test]
    fn parse_repo_url_with_dot_git() {
        let (o, r) = parse_repo_url("https://github.com/foo/bar.git").unwrap();
        assert_eq!(o, "foo");
        assert_eq!(r, "bar");
    }

    #[test]
    fn parse_repo_url_trailing_slash() {
        let (o, r) = parse_repo_url("https://github.com/foo/bar/").unwrap();
        assert_eq!(o, "foo");
        assert_eq!(r, "bar");
    }

    #[test]
    fn parse_repo_url_http_and_www() {
        let (o, r) = parse_repo_url("http://www.github.com/foo/bar").unwrap();
        assert_eq!(o, "foo");
        assert_eq!(r, "bar");
    }

    #[test]
    fn parse_repo_url_ssh_form() {
        let (o, r) = parse_repo_url("git@github.com:foo/bar.git").unwrap();
        assert_eq!(o, "foo");
        assert_eq!(r, "bar");
    }

    #[test]
    fn parse_repo_url_rejects_non_github() {
        assert!(parse_repo_url("https://gitlab.com/foo/bar").is_err());
    }

    #[test]
    fn parse_repo_url_rejects_missing_repo() {
        assert!(parse_repo_url("https://github.com/foo").is_err());
    }

    #[test]
    fn parse_repo_url_strips_extra_path() {
        let (o, r) = parse_repo_url("https://github.com/foo/bar/tree/main").unwrap();
        assert_eq!(o, "foo");
        assert_eq!(r, "bar");
    }

    #[test]
    fn parse_repo_meta_extracts_fields() {
        let json = serde_json::json!({
            "name": "picoclaw",
            "stargazers_count": 42,
            "pushed_at": "2026-04-10T12:00:00Z",
            "license": {"spdx_id": "MIT"},
            "default_branch": "main",
            "html_url": "https://github.com/foo/picoclaw",
            "description": "Tiny claw",
        });
        let m = parse_repo_meta(&json);
        assert_eq!(m.name, "picoclaw");
        assert_eq!(m.stars, 42);
        assert_eq!(m.license_spdx, "MIT");
        assert_eq!(m.default_branch, "main");
        assert_eq!(m.description, "Tiny claw");
    }

    #[test]
    fn parse_repo_meta_handles_missing_license() {
        let json = serde_json::json!({
            "name": "x",
            "stargazers_count": 0,
            "default_branch": "master",
            "pushed_at": "",
            "html_url": "",
            "description": "",
        });
        let m = parse_repo_meta(&json);
        assert_eq!(m.license_spdx, "");
        assert_eq!(m.default_branch, "master");
    }

    #[test]
    fn parse_repo_meta_defaults_branch_to_main_when_missing() {
        let json = serde_json::json!({"name": "x"});
        let m = parse_repo_meta(&json);
        assert_eq!(m.default_branch, "main");
    }

    #[test]
    fn parse_release_extracts_assets() {
        let json = serde_json::json!({
            "tag_name": "v1.2.3",
            "published_at": "2026-04-01T00:00:00Z",
            "assets": [
                {"name": "foo-linux-amd64.tar.gz", "browser_download_url": "https://a/b", "size": 1024},
                {"name": "foo.zip", "browser_download_url": "https://a/c", "size": 2048},
            ],
        });
        let r = parse_release(&json);
        assert_eq!(r.tag_name, "v1.2.3");
        assert_eq!(r.assets.len(), 2);
        assert_eq!(r.assets[0].size, 1024);
    }

    #[test]
    fn parse_file_content_decodes_base64() {
        let raw = base64::engine::general_purpose::STANDARD.encode("hello world");
        let json = serde_json::json!({"encoding": "base64", "content": raw});
        let f = parse_file_content("a.txt", &json).unwrap();
        assert_eq!(f.content, "hello world");
        assert_eq!(f.path, "a.txt");
    }

    #[test]
    fn parse_file_content_handles_multiline_base64() {
        // GitHub wraps base64 output at 60 chars with newlines.
        let raw = format!(
            "{}\n{}\n",
            base64::engine::general_purpose::STANDARD.encode("hello "),
            base64::engine::general_purpose::STANDARD.encode("world"),
        );
        // Make sure base64 of "hello world" comes through when assembled from a
        // real GitHub-style wrapped payload.
        let payload = base64::engine::general_purpose::STANDARD.encode("hello world");
        let wrapped = payload
            .chars()
            .collect::<Vec<_>>()
            .chunks(4)
            .map(|c| c.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join("\n");
        let json = serde_json::json!({"encoding": "base64", "content": wrapped});
        let f = parse_file_content("x", &json).unwrap();
        assert_eq!(f.content, "hello world");
        // Sanity on the multi-line fixture construction.
        assert!(raw.contains('\n'));
    }

    #[test]
    fn parse_file_content_non_base64_passthrough() {
        let json = serde_json::json!({"content": "plain", "encoding": "utf-8"});
        let f = parse_file_content("p", &json).unwrap();
        assert_eq!(f.content, "plain");
    }

    #[test]
    fn github_client_detects_missing_token() {
        // Use a dedicated env var name so we never step on a real GITHUB_TOKEN
        // in the test harness. We only exercise the parsing of the "empty or
        // missing" case.
        core_rs::env::remove_test_env("__SOYEHT_GITHUB_TOKEN_TEST_UNSET__");
        // Building the client reads the real GITHUB_TOKEN from the env — if
        // the developer has one set we skip the negative assertion.
        let c = GitHubClient::new();
        if std::env::var("GITHUB_TOKEN")
            .ok()
            .filter(|t| !t.is_empty())
            .is_none()
        {
            assert!(!c.has_token());
        }
    }
}
