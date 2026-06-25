use std::fmt::Write as _;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{Message, client::IntoClientRequest, http::HeaderValue};

const ATTACH_TOKEN_HEADER: &str = "x-soyeht-household-attach-token";
const DEFAULT_TEST_CLAW: &str = "picoclaw";
const DEFAULT_TARGET_ALIAS: &str = "mac-alpha";
const DEFAULT_GUEST_OS: &str = "linux";
const DEFAULT_TIMEOUT_SECS: u64 = 300;
const DEFAULT_POLL_INTERVAL_SECS: u64 = 3;
const REPORT_BASENAME: &str = "gate-report.md";

#[derive(clap::Args, Clone, Debug)]
#[allow(clippy::struct_excessive_bools)]
pub struct HouseholdPopArgs {
    /// Household listener URL. Keep the real value in .env.local.
    #[arg(long, env = "THEYOS_HH_BASE_URL")]
    pub base_url: Option<String>,

    /// Alias written to the report instead of the real host.
    #[arg(
        long,
        env = "THEYOS_HH_TARGET_ALIAS",
        default_value = DEFAULT_TARGET_ALIAS
    )]
    pub target_alias: String,

    /// Local signer command. The body is sent on stdin; method/path arrive in env.
    #[arg(long, env = "THEYOS_HH_POP_SIGNER_CMD")]
    pub signer_cmd: Option<String>,

    /// Disposable claw selected for the assisted-live flow.
    #[arg(long, env = "THEYOS_HH_TEST_CLAW", default_value = DEFAULT_TEST_CLAW)]
    pub test_claw: String,

    /// Test instance name. Defaults to test-qa-hh-pop-<unix-seconds>.
    #[arg(long, env = "THEYOS_HH_TEST_INSTANCE_NAME")]
    pub test_instance_name: Option<String>,

    /// Guest OS to request for the live create step.
    #[arg(
        long,
        env = "THEYOS_HH_TEST_GUEST_OS",
        default_value = DEFAULT_GUEST_OS,
        value_parser = ["linux", "macos"]
    )]
    pub test_guest_os: String,

    /// Require HH-CLAW-004 to observe GUEST_IMAGE_NOT_READY instead of SKIP.
    #[arg(
        long,
        env = "THEYOS_HH_EXPECT_GUEST_IMAGE_NOT_READY",
        default_value_t = false
    )]
    pub expect_guest_image_not_ready: bool,

    /// Permit uninstalling a claw that was already installed before the gate.
    #[arg(
        long,
        env = "THEYOS_HH_ALLOW_UNINSTALL_PREEXISTING",
        default_value_t = false
    )]
    pub allow_uninstall_preexisting: bool,

    /// Overall live-operation timeout in seconds.
    #[arg(
        long,
        env = "THEYOS_HH_TIMEOUT_SECS",
        default_value_t = DEFAULT_TIMEOUT_SECS
    )]
    pub timeout_secs: u64,

    /// Poll interval in seconds.
    #[arg(
        long,
        env = "THEYOS_HH_POLL_INTERVAL_SECS",
        default_value_t = DEFAULT_POLL_INTERVAL_SECS
    )]
    pub poll_interval_secs: u64,

    /// Directory that will receive gate-report.md.
    #[arg(long, env = "THEYOS_HH_REPORT_DIR")]
    pub report_dir: Option<PathBuf>,
}

pub async fn run_household_pop(args: HouseholdPopArgs) -> i32 {
    let mut runner = HouseholdPopRunner::new(args);
    runner.run().await;
    runner.write_report();
    runner.print_summary();
    runner.exit_code()
}

struct HouseholdPopRunner {
    args: HouseholdPopArgs,
    report: GateReport,
    created_instance_id: Option<String>,
    created_container: Option<String>,
    created_workspace_id: Option<String>,
    installed_by_gate: bool,
    claw_was_ready_before_gate: bool,
}

impl HouseholdPopRunner {
    fn new(args: HouseholdPopArgs) -> Self {
        let started_date = utc_date();
        let git_commit = git_commit_short();
        let instance_name = args
            .test_instance_name
            .clone()
            .unwrap_or_else(default_instance_name);
        Self {
            report: GateReport::new(
                started_date,
                args.target_alias.clone(),
                git_commit,
                instance_name,
            ),
            args,
            created_instance_id: None,
            created_container: None,
            created_workspace_id: None,
            installed_by_gate: false,
            claw_was_ready_before_gate: false,
        }
    }

    async fn run(&mut self) {
        let Some(base_url) = self.args.base_url.as_deref().filter(|url| !url.is_empty()) else {
            self.record(
                "HH-CLAW-001",
                "preflight bootstrap status",
                CaseStatus::Blocked,
                "THEYOS_HH_BASE_URL missing",
            );
            self.block_cases(
                &[
                    "HH-CLAW-002",
                    "HH-CLAW-003",
                    "HH-CLAW-004",
                    "HH-CLAW-005",
                    "HH-CLAW-006",
                    "HH-CLAW-007",
                    "HH-CLAW-008",
                    "HH-CLAW-009",
                    "HH-CLAW-010",
                ],
                "THEYOS_HH_BASE_URL missing",
            );
            return;
        };

        let client = HouseholdClient::new(base_url);
        let bootstrap = self.preflight(&client);
        self.missing_pop_negative(&client);

        let Some(signer_cmd) = self
            .args
            .signer_cmd
            .as_deref()
            .filter(|cmd| !cmd.trim().is_empty())
        else {
            self.block_cases(
                &[
                    "HH-CLAW-003",
                    "HH-CLAW-004",
                    "HH-CLAW-005",
                    "HH-CLAW-006",
                    "HH-CLAW-007",
                    "HH-CLAW-008",
                    "HH-CLAW-009",
                    "HH-CLAW-010",
                ],
                "THEYOS_HH_POP_SIGNER_CMD missing",
            );
            return;
        };
        let signer = PopSigner::new(signer_cmd, &self.args.target_alias);

        self.signed_catalog_and_list(&client, &signer);
        self.guest_image_not_ready(&client, &signer, bootstrap.as_ref());
        self.install_claw(&client, &signer);
        self.create_and_poll_instance(&client, &signer);
        self.attach_token_and_pty(&client, &signer).await;
        self.cleanup(&client, &signer);
        self.final_audit(&client, &signer);
    }

    fn preflight(&mut self, client: &HouseholdClient) -> Option<Value> {
        match client.request("GET", "/bootstrap/status", &[], None) {
            Ok(resp) if resp.status == 200 => {
                let body = parse_json(&resp.body);
                let note = body.as_ref().and_then(guest_image_status).map_or_else(
                    || "reachable".to_string(),
                    |status| format!("reachable; guest_image_status={status}"),
                );
                self.record(
                    "HH-CLAW-001",
                    "preflight bootstrap status",
                    CaseStatus::Pass,
                    note,
                );
                body
            }
            Ok(resp) => {
                self.record(
                    "HH-CLAW-001",
                    "preflight bootstrap status",
                    CaseStatus::Fail,
                    format!("expected 200; observed HTTP {}", resp.status),
                );
                None
            }
            Err(_) => {
                self.record(
                    "HH-CLAW-001",
                    "preflight bootstrap status",
                    CaseStatus::Blocked,
                    "transport error at redacted endpoint",
                );
                None
            }
        }
    }

    fn missing_pop_negative(&mut self, client: &HouseholdClient) {
        match client.request("GET", "/api/v1/household/claws", &[], None) {
            Ok(resp) if resp.status == 401 && resp.body.trim().is_empty() => self.record(
                "HH-CLAW-002",
                "missing PoP catalog rejection",
                CaseStatus::Pass,
                "HTTP 401 with empty body",
            ),
            Ok(resp) => self.record(
                "HH-CLAW-002",
                "missing PoP catalog rejection",
                CaseStatus::Fail,
                format!(
                    "expected HTTP 401 empty body; observed HTTP {} body_empty={}",
                    resp.status,
                    resp.body.trim().is_empty()
                ),
            ),
            Err(_) => self.record(
                "HH-CLAW-002",
                "missing PoP catalog rejection",
                CaseStatus::Blocked,
                "transport error at redacted endpoint",
            ),
        }
    }

    fn signed_catalog_and_list(&mut self, client: &HouseholdClient, signer: &PopSigner) {
        let catalog = client.signed_request(signer, "GET", "/api/v1/household/claws", &[]);
        let instances = client.signed_request(signer, "GET", "/api/v1/household/instances", &[]);
        match (catalog, instances) {
            (Ok(catalog), Ok(instances)) if catalog.status == 200 && instances.status == 200 => {
                self.record(
                    "HH-CLAW-003",
                    "signed catalog and instance list",
                    CaseStatus::Pass,
                    "catalog/list returned HTTP 200",
                );
            }
            (Ok(catalog), Ok(instances)) => self.record(
                "HH-CLAW-003",
                "signed catalog and instance list",
                CaseStatus::Fail,
                format!(
                    "expected both HTTP 200; observed catalog={} instances={}",
                    catalog.status, instances.status
                ),
            ),
            (Err(error), _) | (_, Err(error)) => self.record(
                "HH-CLAW-003",
                "signed catalog and instance list",
                error.status(),
                error.safe_note(),
            ),
        }
    }

    fn guest_image_not_ready(
        &mut self,
        client: &HouseholdClient,
        signer: &PopSigner,
        bootstrap: Option<&Value>,
    ) {
        if self.args.test_guest_os != "macos" && !self.args.expect_guest_image_not_ready {
            self.record(
                "HH-CLAW-004",
                "guest-image-not-ready visibility",
                CaseStatus::Skip,
                "test guest OS is not macos",
            );
            return;
        }

        if !self.args.expect_guest_image_not_ready {
            match bootstrap.and_then(guest_image_status).as_deref() {
                Some("done") => {
                    self.record(
                        "HH-CLAW-004",
                        "guest-image-not-ready visibility",
                        CaseStatus::Skip,
                        "guest image already ready",
                    );
                    return;
                }
                Some("not_applicable") | None => {
                    self.record(
                        "HH-CLAW-004",
                        "guest-image-not-ready visibility",
                        CaseStatus::Skip,
                        "guest image not-ready state not observable",
                    );
                    return;
                }
                Some(_) => {}
            }
        }

        let probe_name = format!("{}-guest-image-probe", self.report.instance_name);
        let body = create_instance_body(&probe_name, &self.args.test_claw, "macos");
        match client.signed_request(signer, "POST", "/api/v1/household/instances", &body) {
            Ok(resp) if resp.status == 409 && json_code_is(&resp.body, "GUEST_IMAGE_NOT_READY") => {
                self.record(
                    "HH-CLAW-004",
                    "guest-image-not-ready visibility",
                    CaseStatus::Pass,
                    "HTTP 409 GUEST_IMAGE_NOT_READY observed",
                );
            }
            Ok(resp) if self.args.expect_guest_image_not_ready => {
                let cleanup_note = cleanup_guest_image_probe(client, signer, &resp);
                self.record(
                    "HH-CLAW-004",
                    "guest-image-not-ready visibility",
                    CaseStatus::Fail,
                    format!(
                        "expected HTTP 409 GUEST_IMAGE_NOT_READY; observed HTTP {}{cleanup_note}",
                        resp.status
                    ),
                );
            }
            Ok(resp) => {
                let cleanup_note = cleanup_guest_image_probe(client, signer, &resp);
                self.record(
                    "HH-CLAW-004",
                    "guest-image-not-ready visibility",
                    CaseStatus::Skip,
                    format!(
                        "guest-image-not-ready was not observed; create probe returned HTTP {}{cleanup_note}",
                        resp.status
                    ),
                );
            }
            Err(error) => self.record(
                "HH-CLAW-004",
                "guest-image-not-ready visibility",
                error.status(),
                error.safe_note(),
            ),
        }
    }

    fn install_claw(&mut self, client: &HouseholdClient, signer: &PopSigner) {
        let availability_path = format!(
            "/api/v1/household/claws/{}/availability",
            encode_path_segment(&self.args.test_claw)
        );
        let preflight_ready = client
            .signed_request(signer, "GET", &availability_path, &[])
            .ok()
            .and_then(|resp| parse_json(&resp.body))
            .is_some_and(|body| availability_is_ready(&body));
        self.claw_was_ready_before_gate = preflight_ready;

        let install_path = format!(
            "/api/v1/household/claws/{}/install",
            encode_path_segment(&self.args.test_claw)
        );
        match client.signed_request(signer, "POST", &install_path, &[]) {
            Ok(resp) if resp.status == 200 => {
                self.installed_by_gate = !preflight_ready;
                self.poll_claw_ready(client, signer, &availability_path);
            }
            Ok(resp) if resp.status == 400 && response_says_already_ready(&resp.body) => {
                self.claw_was_ready_before_gate = true;
                self.record(
                    "HH-CLAW-005",
                    "install selected test claw",
                    CaseStatus::Pass,
                    "claw was already ready before gate",
                );
            }
            Ok(resp) => self.record(
                "HH-CLAW-005",
                "install selected test claw",
                CaseStatus::Fail,
                format!("install returned HTTP {}", resp.status),
            ),
            Err(error) => self.record(
                "HH-CLAW-005",
                "install selected test claw",
                error.status(),
                error.safe_note(),
            ),
        }
    }

    fn poll_claw_ready(&mut self, client: &HouseholdClient, signer: &PopSigner, path: &str) {
        let deadline = Instant::now() + Duration::from_secs(self.args.timeout_secs);
        loop {
            match client.signed_request(signer, "GET", path, &[]) {
                Ok(resp) if resp.status == 200 => {
                    if parse_json(&resp.body).is_some_and(|body| availability_is_ready(&body)) {
                        self.record(
                            "HH-CLAW-005",
                            "install selected test claw",
                            CaseStatus::Pass,
                            "availability reached ready/creatable",
                        );
                        return;
                    }
                }
                Ok(resp) => {
                    self.record(
                        "HH-CLAW-005",
                        "install selected test claw",
                        CaseStatus::Fail,
                        format!("availability poll returned HTTP {}", resp.status),
                    );
                    return;
                }
                Err(error) => {
                    self.record(
                        "HH-CLAW-005",
                        "install selected test claw",
                        error.status(),
                        error.safe_note(),
                    );
                    return;
                }
            }

            if Instant::now() >= deadline {
                self.record(
                    "HH-CLAW-005",
                    "install selected test claw",
                    CaseStatus::Fail,
                    "timed out waiting for ready availability",
                );
                return;
            }
            std::thread::sleep(Duration::from_secs(self.args.poll_interval_secs));
        }
    }

    fn create_and_poll_instance(&mut self, client: &HouseholdClient, signer: &PopSigner) {
        let body = create_instance_body(
            &self.report.instance_name,
            &self.args.test_claw,
            &self.args.test_guest_os,
        );
        match client.signed_request(signer, "POST", "/api/v1/household/instances", &body) {
            Ok(resp) if resp.status == 202 => {
                let Some(body) = parse_json(&resp.body) else {
                    self.record(
                        "HH-CLAW-006",
                        "create instance and poll status",
                        CaseStatus::Fail,
                        "create returned unparseable JSON",
                    );
                    return;
                };
                let Some(id) = body.get("id").and_then(Value::as_str).map(str::to_string) else {
                    self.record(
                        "HH-CLAW-006",
                        "create instance and poll status",
                        CaseStatus::Fail,
                        "create response missing id",
                    );
                    return;
                };
                let Some(container) = body
                    .get("container")
                    .and_then(Value::as_str)
                    .map(str::to_string)
                else {
                    self.record(
                        "HH-CLAW-006",
                        "create instance and poll status",
                        CaseStatus::Fail,
                        "create response missing container",
                    );
                    return;
                };
                self.created_instance_id = Some(id.clone());
                self.created_container = Some(container);
                self.poll_instance_active(client, signer, &id);
            }
            Ok(resp) if resp.status == 409 && json_code_is(&resp.body, "GUEST_IMAGE_NOT_READY") => {
                self.record(
                    "HH-CLAW-006",
                    "create instance and poll status",
                    CaseStatus::Blocked,
                    "guest image not ready blocked create",
                );
            }
            Ok(resp) => self.record(
                "HH-CLAW-006",
                "create instance and poll status",
                CaseStatus::Fail,
                format!("create returned HTTP {}", resp.status),
            ),
            Err(error) => self.record(
                "HH-CLAW-006",
                "create instance and poll status",
                error.status(),
                error.safe_note(),
            ),
        }
    }

    fn poll_instance_active(&mut self, client: &HouseholdClient, signer: &PopSigner, id: &str) {
        let path = format!(
            "/api/v1/household/instances/{}/status",
            encode_path_segment(id)
        );
        let deadline = Instant::now() + Duration::from_secs(self.args.timeout_secs);
        loop {
            match client.signed_request(signer, "GET", &path, &[]) {
                Ok(resp) if resp.status == 200 => {
                    let status = parse_json(&resp.body)
                        .and_then(|body| {
                            body.get("status")
                                .and_then(Value::as_str)
                                .map(str::to_string)
                        })
                        .unwrap_or_default();
                    if status == "active" {
                        self.record(
                            "HH-CLAW-006",
                            "create instance and poll status",
                            CaseStatus::Pass,
                            "instance reached active",
                        );
                        return;
                    }
                    if matches!(status.as_str(), "failed" | "error") {
                        self.record(
                            "HH-CLAW-006",
                            "create instance and poll status",
                            CaseStatus::Fail,
                            "instance reached failure status",
                        );
                        return;
                    }
                }
                Ok(resp) => {
                    self.record(
                        "HH-CLAW-006",
                        "create instance and poll status",
                        CaseStatus::Fail,
                        format!("status poll returned HTTP {}", resp.status),
                    );
                    return;
                }
                Err(error) => {
                    self.record(
                        "HH-CLAW-006",
                        "create instance and poll status",
                        error.status(),
                        error.safe_note(),
                    );
                    return;
                }
            }

            if Instant::now() >= deadline {
                self.record(
                    "HH-CLAW-006",
                    "create instance and poll status",
                    CaseStatus::Fail,
                    "timed out waiting for active status",
                );
                return;
            }
            std::thread::sleep(Duration::from_secs(self.args.poll_interval_secs));
        }
    }

    async fn attach_token_and_pty(&mut self, client: &HouseholdClient, signer: &PopSigner) {
        let Some(container) = self.created_container.clone() else {
            self.record(
                "HH-CLAW-007",
                "attach-token query boundary",
                CaseStatus::Skip,
                "no created container",
            );
            self.record(
                "HH-CLAW-008",
                "household PTY round trip",
                CaseStatus::Skip,
                "no created container",
            );
            return;
        };

        let workspace_path = format!(
            "/api/v1/household/terminals/{}/workspaces",
            encode_path_segment(&container)
        );
        let workspace_body = json!({"display_name": "Household PoP E2E"}).to_string();
        let workspace =
            match client.signed_request(signer, "POST", &workspace_path, workspace_body.as_bytes())
            {
                Ok(resp) if resp.status == 200 => parse_json(&resp.body),
                Ok(resp) => {
                    self.record(
                        "HH-CLAW-007",
                        "attach-token query boundary",
                        CaseStatus::Fail,
                        format!("workspace create returned HTTP {}", resp.status),
                    );
                    self.record(
                        "HH-CLAW-008",
                        "household PTY round trip",
                        CaseStatus::Skip,
                        "workspace create failed",
                    );
                    return;
                }
                Err(error) => {
                    self.record(
                        "HH-CLAW-007",
                        "attach-token query boundary",
                        error.status(),
                        error.safe_note(),
                    );
                    self.record(
                        "HH-CLAW-008",
                        "household PTY round trip",
                        CaseStatus::Skip,
                        "workspace create failed",
                    );
                    return;
                }
            };
        let Some(workspace_id) = workspace
            .as_ref()
            .and_then(|body| body.pointer("/workspace/id"))
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            self.record(
                "HH-CLAW-007",
                "attach-token query boundary",
                CaseStatus::Fail,
                "workspace create response missing workspace id",
            );
            self.record(
                "HH-CLAW-008",
                "household PTY round trip",
                CaseStatus::Skip,
                "workspace id missing",
            );
            return;
        };
        self.created_workspace_id = Some(workspace_id.clone());

        let attach_path = format!(
            "/api/v1/household/terminals/{}/attach-token",
            encode_path_segment(&container)
        );
        let attach_body = json!({"workspace_id": workspace_id}).to_string();
        let token =
            match client.signed_request(signer, "POST", &attach_path, attach_body.as_bytes()) {
                Ok(resp) if resp.status == 200 => parse_json(&resp.body).and_then(|body| {
                    body.get("token")
                        .and_then(Value::as_str)
                        .map(str::to_string)
                }),
                Ok(resp) => {
                    self.record(
                        "HH-CLAW-007",
                        "attach-token query boundary",
                        CaseStatus::Fail,
                        format!("attach-token mint returned HTTP {}", resp.status),
                    );
                    self.record(
                        "HH-CLAW-008",
                        "household PTY round trip",
                        CaseStatus::Skip,
                        "attach-token mint failed",
                    );
                    return;
                }
                Err(error) => {
                    self.record(
                        "HH-CLAW-007",
                        "attach-token query boundary",
                        error.status(),
                        error.safe_note(),
                    );
                    self.record(
                        "HH-CLAW-008",
                        "household PTY round trip",
                        CaseStatus::Skip,
                        "attach-token mint failed",
                    );
                    return;
                }
            };
        let Some(token) = token else {
            self.record(
                "HH-CLAW-007",
                "attach-token query boundary",
                CaseStatus::Fail,
                "attach-token response missing token",
            );
            self.record(
                "HH-CLAW-008",
                "household PTY round trip",
                CaseStatus::Skip,
                "attach-token missing",
            );
            return;
        };

        let query_path = format!(
            "/api/v1/household/terminals/{}/pty?session={}&token={}",
            encode_path_segment(&container),
            encode_query_value(&workspace_id),
            encode_query_value(&token)
        );
        let query_status = match client.request("GET", &query_path, &[], None) {
            Ok(resp) if resp.status == 401 && resp.body.trim().is_empty() => 401,
            Ok(resp) => resp.status,
            Err(_) => 0,
        };

        let header_positive = if query_status == 401 {
            household_pty_roundtrip(
                client.base_url(),
                &container,
                &workspace_id,
                &token,
                Duration::from_secs(self.args.timeout_secs.min(60)),
            )
            .await
            .is_ok()
        } else {
            false
        };

        match evaluate_query_token_boundary(query_status, header_positive) {
            CaseStatus::Pass => {
                self.record(
                    "HH-CLAW-007",
                    "attach-token query boundary",
                    CaseStatus::Pass,
                    "query token rejected and header token accepted",
                );
                self.record(
                    "HH-CLAW-008",
                    "household PTY round trip",
                    CaseStatus::Pass,
                    "PTY marker observed",
                );
            }
            CaseStatus::Fail if query_status != 401 => {
                self.record(
                    "HH-CLAW-007",
                    "attach-token query boundary",
                    CaseStatus::Fail,
                    format!("expected query-token HTTP 401; observed HTTP {query_status}"),
                );
                self.record(
                    "HH-CLAW-008",
                    "household PTY round trip",
                    CaseStatus::Skip,
                    "query-token rejection did not pass",
                );
            }
            CaseStatus::Fail => {
                self.record(
                    "HH-CLAW-007",
                    "attach-token query boundary",
                    CaseStatus::Fail,
                    "header-positive attach failed after query-token rejection",
                );
                self.record(
                    "HH-CLAW-008",
                    "household PTY round trip",
                    CaseStatus::Fail,
                    "PTY marker was not observed",
                );
            }
            CaseStatus::Skip | CaseStatus::Blocked => unreachable!("boundary evaluator is binary"),
        }
    }

    fn cleanup(&mut self, client: &HouseholdClient, signer: &PopSigner) {
        let mut notes = Vec::new();
        let mut failed = false;

        if let Some(id) = self.created_instance_id.as_deref() {
            let path = format!("/api/v1/household/instances/{}", encode_path_segment(id));
            match client.signed_request(signer, "DELETE", &path, &[]) {
                Ok(resp) if resp.status == 204 || resp.status == 404 => {
                    notes.push("instance delete accepted");
                }
                Ok(resp) => {
                    failed = true;
                    notes.push(if resp.status == 401 {
                        "instance delete unauthorized"
                    } else {
                        "instance delete returned unexpected status"
                    });
                }
                Err(_) => {
                    failed = true;
                    notes.push("instance delete transport error");
                }
            }
        } else {
            notes.push("no created instance");
        }

        if self.installed_by_gate
            || (self.claw_was_ready_before_gate && self.args.allow_uninstall_preexisting)
        {
            let path = format!(
                "/api/v1/household/claws/{}/uninstall",
                encode_path_segment(&self.args.test_claw)
            );
            match client.signed_request(signer, "POST", &path, &[]) {
                Ok(resp) if resp.status == 200 || resp.status == 400 => {
                    notes.push("claw uninstall requested or already unavailable");
                }
                Ok(_) | Err(_) => {
                    failed = true;
                    notes.push("claw uninstall failed");
                }
            }
        } else if self.claw_was_ready_before_gate {
            notes.push("preexisting claw preserved");
        } else {
            notes.push("no claw uninstall needed");
        }

        self.record(
            "HH-CLAW-009",
            "cleanup",
            if failed {
                CaseStatus::Fail
            } else {
                CaseStatus::Pass
            },
            notes.join("; "),
        );
    }

    fn final_audit(&mut self, client: &HouseholdClient, signer: &PopSigner) {
        match client.signed_request(signer, "GET", "/api/v1/household/instances", &[]) {
            Ok(resp) if resp.status == 200 => {
                let leftover = parse_json(&resp.body).is_some_and(|body| {
                    body.pointer("/data")
                        .and_then(Value::as_array)
                        .is_some_and(|items| items.iter().any(|item| self.item_matches_run(item)))
                });
                self.record(
                    "HH-CLAW-010",
                    "final audit",
                    if leftover {
                        CaseStatus::Fail
                    } else {
                        CaseStatus::Pass
                    },
                    if leftover {
                        "test instance still visible"
                    } else {
                        "no matching test instance visible"
                    },
                );
            }
            Ok(resp) => self.record(
                "HH-CLAW-010",
                "final audit",
                CaseStatus::Fail,
                format!("instance list returned HTTP {}", resp.status),
            ),
            Err(error) => self.record(
                "HH-CLAW-010",
                "final audit",
                error.status(),
                error.safe_note(),
            ),
        }
    }

    fn item_matches_run(&self, item: &Value) -> bool {
        let instance_name = self.report.instance_name.as_str();
        let id = self.created_instance_id.as_deref();
        let container = self.created_container.as_deref();
        ["id", "name", "container"].iter().any(|key| {
            item.get(*key).and_then(Value::as_str).is_some_and(|value| {
                value == instance_name || Some(value) == id || Some(value) == container
            })
        })
    }

    fn block_cases(&mut self, ids: &[&'static str], note: &str) {
        for id in ids {
            self.record(*id, description_for_case(id), CaseStatus::Blocked, note);
        }
    }

    fn record(
        &mut self,
        id: &'static str,
        description: &'static str,
        status: CaseStatus,
        note: impl Into<String>,
    ) {
        self.report.push(CaseReport {
            id,
            description,
            status,
            note: redact_sensitive(&note.into()),
        });
    }

    fn write_report(&mut self) {
        match self.report.write(self.args.report_dir.as_deref()) {
            Ok(rel_path) => {
                self.report.report_path = Some(rel_path.clone());
                eprintln!("[household-pop] report: {rel_path}");
            }
            Err(()) => {
                eprintln!("[household-pop] report write failed");
            }
        }
    }

    fn print_summary(&self) {
        eprintln!(
            "[household-pop] target={} result={} pass={} fail={} skip={} blocked={}",
            self.report.target_alias,
            self.report.overall_result(),
            self.report.count(CaseStatus::Pass),
            self.report.count(CaseStatus::Fail),
            self.report.count(CaseStatus::Skip),
            self.report.count(CaseStatus::Blocked)
        );
        for case in &self.report.cases {
            eprintln!("[household-pop] {} {} {}", case.status, case.id, case.note);
        }
    }

    fn exit_code(&self) -> i32 {
        if self
            .report
            .cases
            .iter()
            .any(|case| case.status == CaseStatus::Fail)
        {
            1
        } else if self
            .report
            .cases
            .iter()
            .any(|case| case.status == CaseStatus::Blocked)
        {
            2
        } else {
            0
        }
    }
}

struct HouseholdClient {
    base_url: String,
    agent: ureq::Agent,
}

impl HouseholdClient {
    fn new(base_url: &str) -> Self {
        Self {
            base_url: base_url.trim_end_matches('/').to_string(),
            agent: ureq::AgentBuilder::new()
                .timeout(Duration::from_secs(15))
                .build(),
        }
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }

    fn signed_request(
        &self,
        signer: &PopSigner,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Result<HttpResponse, GateError> {
        let auth = signer.sign(method, path, body)?;
        self.request(method, path, body, Some(&auth))
    }

    fn request(
        &self,
        method: &str,
        path: &str,
        body: &[u8],
        authorization: Option<&str>,
    ) -> Result<HttpResponse, GateError> {
        let url = format!("{}{}", self.base_url, path);
        let mut request = self.agent.request(method, &url);
        if let Some(authorization) = authorization {
            request = request.set("Authorization", authorization);
        }
        if !body.is_empty() {
            request = request.set("Content-Type", "application/json");
        }

        let result = if body.is_empty() {
            request.call()
        } else {
            request.send_bytes(body)
        };

        match result {
            Ok(resp) => Ok(HttpResponse::from_ureq(resp)),
            Err(ureq::Error::Status(status, resp)) => Ok(HttpResponse::from_status(status, resp)),
            Err(ureq::Error::Transport(_)) => Err(GateError::Transport),
        }
    }
}

struct PopSigner {
    command: String,
    target_alias: String,
}

impl PopSigner {
    fn new(command: &str, target_alias: &str) -> Self {
        Self {
            command: command.to_string(),
            target_alias: target_alias.to_string(),
        }
    }

    fn sign(&self, method: &str, path: &str, body: &[u8]) -> Result<String, GateError> {
        let mut child = Command::new("sh")
            .arg("-c")
            .arg(&self.command)
            .env("THEYOS_HH_SIGN_METHOD", method)
            .env("THEYOS_HH_SIGN_PATH", path)
            .env("THEYOS_HH_SIGN_TARGET_ALIAS", &self.target_alias)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| GateError::Signer)?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(body).map_err(|_| GateError::Signer)?;
        }

        let output = child.wait_with_output().map_err(|_| GateError::Signer)?;
        if !output.status.success() {
            return Err(GateError::Signer);
        }
        let stdout = String::from_utf8(output.stdout).map_err(|_| GateError::Signer)?;
        normalize_authorization_output(&stdout).ok_or(GateError::Signer)
    }
}

struct HttpResponse {
    status: u16,
    body: String,
}

impl HttpResponse {
    fn from_ureq(resp: ureq::Response) -> Self {
        let status = resp.status();
        let body = resp.into_string().unwrap_or_default();
        Self { status, body }
    }

    fn from_status(status: u16, resp: ureq::Response) -> Self {
        let body = resp.into_string().unwrap_or_default();
        Self { status, body }
    }
}

enum GateError {
    Transport,
    Signer,
}

impl GateError {
    fn status(&self) -> CaseStatus {
        match self {
            Self::Transport => CaseStatus::Blocked,
            Self::Signer => CaseStatus::Blocked,
        }
    }

    fn safe_note(&self) -> &'static str {
        match self {
            Self::Transport => "transport error at redacted endpoint",
            Self::Signer => "PoP signer failed without exposing signer output",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaseStatus {
    Pass,
    Fail,
    Skip,
    Blocked,
}

impl std::fmt::Display for CaseStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Skip => "SKIP",
            Self::Blocked => "BLOCKED",
        };
        f.write_str(value)
    }
}

struct CaseReport {
    id: &'static str,
    description: &'static str,
    status: CaseStatus,
    note: String,
}

struct GateReport {
    started_date: String,
    target_alias: String,
    git_commit: String,
    instance_name: String,
    cases: Vec<CaseReport>,
    report_path: Option<String>,
}

impl GateReport {
    fn new(
        started_date: String,
        target_alias: String,
        git_commit: String,
        instance_name: String,
    ) -> Self {
        Self {
            started_date,
            target_alias,
            git_commit,
            instance_name,
            cases: Vec::new(),
            report_path: None,
        }
    }

    fn push(&mut self, case: CaseReport) {
        if let Some(existing) = self
            .cases
            .iter_mut()
            .find(|existing| existing.id == case.id)
        {
            *existing = case;
        } else {
            self.cases.push(case);
        }
    }

    fn count(&self, status: CaseStatus) -> usize {
        self.cases
            .iter()
            .filter(|case| case.status == status)
            .count()
    }

    fn overall_result(&self) -> &'static str {
        if self.count(CaseStatus::Fail) > 0 {
            "FAIL"
        } else if self.count(CaseStatus::Blocked) > 0 {
            "BLOCKED"
        } else {
            "PASS"
        }
    }

    fn write(&self, report_dir: Option<&Path>) -> Result<String, ()> {
        let (dir, rel_dir) = report_directory(report_dir, &self.started_date)?;
        fs::create_dir_all(&dir).map_err(|_| ())?;
        let report_path = dir.join(REPORT_BASENAME);
        let rel_path = format!("{rel_dir}/{REPORT_BASENAME}");
        fs::write(&report_path, self.render()).map_err(|_| ())?;
        Ok(rel_path)
    }

    fn render(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(out, "# Household PoP Claw Store Gate");
        let _ = writeln!(out);
        let _ = writeln!(out, "**Date**: {}", self.started_date);
        let _ = writeln!(out, "**Target Alias**: {}", self.target_alias);
        let _ = writeln!(out, "**Git Commit**: {}", self.git_commit);
        let _ = writeln!(
            out,
            "**Plan Reference**: QA/domains/household-pop-claw-store.md"
        );
        let _ = writeln!(out, "**Result**: {}", self.overall_result());
        let _ = writeln!(out);
        let _ = writeln!(
            out,
            "This report intentionally omits real URLs, hostnames, IPs, auth headers, PoP headers, attach tokens, p_id/hh_id values, host labels, and raw terminal output."
        );
        let _ = writeln!(out);
        let _ = writeln!(out, "## Summary");
        let _ = writeln!(out);
        let _ = writeln!(out, "| Result | Count |");
        let _ = writeln!(out, "|--------|-------|");
        for status in [
            CaseStatus::Pass,
            CaseStatus::Fail,
            CaseStatus::Skip,
            CaseStatus::Blocked,
        ] {
            let _ = writeln!(out, "| {status} | {} |", self.count(status));
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "## Test Results");
        let _ = writeln!(out);
        let _ = writeln!(out, "| ID | Description | Status | Notes |");
        let _ = writeln!(out, "|----|-------------|--------|-------|");
        for case in &self.cases {
            let _ = writeln!(
                out,
                "| {} | {} | {} | {} |",
                case.id,
                case.description,
                case.status,
                markdown_cell(&case.note)
            );
        }
        let _ = writeln!(out);
        let _ = writeln!(out, "## Cleanup");
        let _ = writeln!(out);
        let cleanup = self
            .cases
            .iter()
            .find(|case| case.id == "HH-CLAW-009")
            .map_or("not run", |case| case.note.as_str());
        let _ = writeln!(out, "- Cleanup status: {cleanup}");
        let _ = writeln!(out, "- Test instance alias: {}", self.instance_name);
        out
    }
}

fn description_for_case(id: &str) -> &'static str {
    match id {
        "HH-CLAW-001" => "preflight bootstrap status",
        "HH-CLAW-002" => "missing PoP catalog rejection",
        "HH-CLAW-003" => "signed catalog and instance list",
        "HH-CLAW-004" => "guest-image-not-ready visibility",
        "HH-CLAW-005" => "install selected test claw",
        "HH-CLAW-006" => "create instance and poll status",
        "HH-CLAW-007" => "attach-token query boundary",
        "HH-CLAW-008" => "household PTY round trip",
        "HH-CLAW-009" => "cleanup",
        "HH-CLAW-010" => "final audit",
        _ => "household PoP gate",
    }
}

async fn household_pty_roundtrip(
    base_url: &str,
    container: &str,
    session: &str,
    attach_token: &str,
    overall_timeout: Duration,
) -> Result<(), ()> {
    let ws_url = household_ws_url(base_url, container, session)?;
    let mut request = ws_url.into_client_request().map_err(|_| ())?;
    request.headers_mut().insert(
        ATTACH_TOKEN_HEADER,
        HeaderValue::from_str(attach_token).map_err(|_| ())?,
    );

    let (mut stream, _) = connect_async(request).await.map_err(|_| ())?;
    let marker = format!("__HH_POP_OK_{}__", unix_seconds());
    let deadline = Instant::now() + overall_timeout;

    stream
        .send(Message::Text(
            json!({"type": "resize", "cols": 120, "rows": 32})
                .to_string()
                .into(),
        ))
        .await
        .map_err(|_| ())?;
    stream
        .send(Message::Text(
            json!({"type": "input", "data": format!("printf '{marker}\\n'\r")})
                .to_string()
                .into(),
        ))
        .await
        .map_err(|_| ())?;

    let mut transcript = String::new();
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(());
        }
        let Some(message) = timeout(remaining.min(Duration::from_secs(20)), stream.next())
            .await
            .map_err(|_| ())?
        else {
            return Err(());
        };
        match message.map_err(|_| ())? {
            Message::Text(text) => {
                transcript.push_str(text.as_ref());
                trim_transcript(&mut transcript);
            }
            Message::Binary(bytes) => {
                transcript.push_str(&String::from_utf8_lossy(&bytes));
                trim_transcript(&mut transcript);
            }
            Message::Close(_) => return Err(()),
            Message::Ping(_) | Message::Pong(_) | Message::Frame(_) => {}
        }
        if transcript.contains(&marker) {
            let _ = stream.close(None).await;
            return Ok(());
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn household_ws_url(base_url: &str, container: &str, session: &str) -> Result<String, ()> {
    let base_url = base_url.trim_end_matches('/');
    let ws_base = if let Some(rest) = base_url.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = base_url.strip_prefix("http://") {
        format!("ws://{rest}")
    } else {
        return Err(());
    };
    Ok(format!(
        "{ws_base}/api/v1/household/terminals/{}/pty?session={}",
        encode_path_segment(container),
        encode_query_value(session)
    ))
}

fn evaluate_query_token_boundary(query_status: u16, header_positive: bool) -> CaseStatus {
    if query_status == 401 && header_positive {
        CaseStatus::Pass
    } else {
        CaseStatus::Fail
    }
}

fn normalize_authorization_output(output: &str) -> Option<String> {
    let line = output
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())?;
    let value = line
        .strip_prefix("Authorization:")
        .or_else(|| line.strip_prefix("authorization:"))
        .map_or(line, str::trim);
    if value.starts_with("Soyeht-PoP ") || value.starts_with("Soyeht-PoP\t") {
        Some(value.to_string())
    } else {
        None
    }
}

fn create_instance_body(name: &str, claw: &str, guest_os: &str) -> Vec<u8> {
    json!({
        "name": name,
        "claw_type": claw,
        "guest_os": guest_os,
        "cpu_cores": 1,
        "ram_mb": 512,
        "disk_gb": 5
    })
    .to_string()
    .into_bytes()
}

fn parse_json(body: &str) -> Option<Value> {
    serde_json::from_str(body).ok()
}

fn json_code_is(body: &str, expected: &str) -> bool {
    parse_json(body)
        .and_then(|value| {
            value
                .get("code")
                .and_then(Value::as_str)
                .map(str::to_string)
        })
        .is_some_and(|code| code == expected)
}

fn response_says_already_ready(body: &str) -> bool {
    parse_json(body).is_some_and(|value| {
        value
            .get("code")
            .and_then(Value::as_str)
            .is_some_and(|code| code == "ALREADY_READY")
            || value
                .get("error")
                .and_then(Value::as_str)
                .is_some_and(|error| error.contains("already ready"))
    })
}

fn cleanup_guest_image_probe(
    client: &HouseholdClient,
    signer: &PopSigner,
    response: &HttpResponse,
) -> &'static str {
    if response.status != 202 {
        return "";
    }
    let Some(id) = parse_json(&response.body)
        .and_then(|body| body.get("id").and_then(Value::as_str).map(str::to_string))
    else {
        return "; accepted probe cleanup could not find id";
    };
    let path = format!("/api/v1/household/instances/{}", encode_path_segment(&id));
    match client.signed_request(signer, "DELETE", &path, &[]) {
        Ok(resp) if resp.status == 204 || resp.status == 404 => {
            "; accepted probe cleanup requested"
        }
        Ok(_) | Err(_) => "; accepted probe cleanup failed",
    }
}

fn availability_is_ready(value: &Value) -> bool {
    value
        .pointer("/install/status")
        .and_then(Value::as_str)
        .is_some_and(|status| matches!(status, "succeeded" | "ready"))
        || value
            .pointer("/overall/state")
            .and_then(Value::as_str)
            .is_some_and(|state| state == "creatable")
}

fn guest_image_status(value: &Value) -> Option<String> {
    value
        .get("guest_image_status")
        .or_else(|| value.pointer("/guest_image/status"))
        .and_then(Value::as_str)
        .map(str::to_string)
}

fn report_directory(report_dir: Option<&Path>, date: &str) -> Result<(PathBuf, String), ()> {
    if let Some(report_dir) = report_dir {
        return Ok((report_dir.to_path_buf(), "custom-report-dir".to_string()));
    }
    let repo_root = core_rs::path::resolve_repo_root().map_err(|_| ())?;
    let rel_dir = format!("QA/runs/{date}-household-pop-claw-store");
    Ok((repo_root.join(&rel_dir), rel_dir))
}

fn default_instance_name() -> String {
    format!("test-qa-hh-pop-{}", unix_seconds())
}

fn utc_date() -> String {
    Command::new("date")
        .arg("-u")
        .arg("+%F")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|date| date.trim().to_string())
        .filter(|date| !date.is_empty())
        .unwrap_or_else(|| unix_seconds().to_string())
}

fn git_commit_short() -> String {
    Command::new("git")
        .arg("rev-parse")
        .arg("--short")
        .arg("HEAD")
        .output()
        .ok()
        .filter(|output| output.status.success())
        .and_then(|output| String::from_utf8(output.stdout).ok())
        .map(|commit| commit.trim().to_string())
        .filter(|commit| !commit.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn unix_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn encode_path_segment(raw: &str) -> String {
    percent_encode(raw)
}

fn encode_query_value(raw: &str) -> String {
    percent_encode(raw)
}

fn percent_encode(raw: &str) -> String {
    let mut out = String::new();
    for byte in raw.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            let _ = write!(out, "%{byte:02X}");
        }
    }
    out
}

fn trim_transcript(transcript: &mut String) {
    const MAX_TRANSCRIPT_LEN: usize = 4096;
    if transcript.len() > MAX_TRANSCRIPT_LEN {
        let start = transcript.len().saturating_sub(MAX_TRANSCRIPT_LEN);
        transcript.replace_range(..start, "");
    }
}

fn markdown_cell(note: &str) -> String {
    note.replace('|', "\\|").replace('\n', " ")
}

fn redact_sensitive(input: &str) -> String {
    if input.contains("Authorization")
        || input.contains("authorization")
        || input.contains("Soyeht-PoP")
        || input.contains(ATTACH_TOKEN_HEADER)
        || input.contains("token=")
    {
        return "[redacted-sensitive]".to_string();
    }

    let mut output = redact_urlish_words(input);
    output = redact_json_key(&output, "token");
    output = redact_json_key(&output, "p_id");
    output = redact_json_key(&output, "hh_id");
    output = redact_json_key(&output, "host_label");
    output
}

fn redact_urlish_words(input: &str) -> String {
    input
        .split_whitespace()
        .map(|word| {
            if ["http://", "https://", "ws://", "wss://"]
                .iter()
                .any(|prefix| word.contains(prefix))
            {
                "[redacted-url]"
            } else {
                word
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn redact_json_key(input: &str, key: &str) -> String {
    let quoted = format!("\"{key}\"");
    let Some(index) = input.find(&quoted) else {
        return input.to_string();
    };
    let Some(colon_offset) = input[index + quoted.len()..].find(':') else {
        return input.to_string();
    };
    let value_start = index + quoted.len() + colon_offset + 1;
    let rest = &input[value_start..];
    let suffix_start = rest.find([',', '}', '\n']).unwrap_or(rest.len());
    format!(
        "{} \"[redacted]\"{}",
        &input[..value_start],
        &rest[suffix_start..]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redaction_removes_sensitive_values_from_notes() {
        let note = concat!(
            "failed http://100.64.0.10:9999/path ",
            "Authorization: Soyeht-PoP v1:p_id-alpha:123:secret ",
            "x-soyeht-household-attach-token abc ",
            "{\"token\":\"attach-token-alpha\",\"p_id\":\"p-alpha\",\"hh_id\":\"hh-alpha\",",
            "\"host_label\":\"real-host\"}"
        );

        let redacted = redact_sensitive(note);
        assert!(!redacted.contains("100.64.0.10"));
        assert!(!redacted.contains("attach-token-alpha"));
        assert!(!redacted.contains("p-alpha"));
        assert!(!redacted.contains("hh-alpha"));
        assert!(!redacted.contains("real-host"));
        assert!(redacted.contains("[redacted"));
    }

    #[test]
    fn missing_signer_blocks_signed_cases() {
        let mut runner = HouseholdPopRunner::new(HouseholdPopArgs {
            base_url: None,
            target_alias: DEFAULT_TARGET_ALIAS.to_string(),
            signer_cmd: None,
            test_claw: DEFAULT_TEST_CLAW.to_string(),
            test_instance_name: Some("test-qa-hh-pop-unit".to_string()),
            test_guest_os: DEFAULT_GUEST_OS.to_string(),
            expect_guest_image_not_ready: false,
            allow_uninstall_preexisting: false,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
            poll_interval_secs: DEFAULT_POLL_INTERVAL_SECS,
            report_dir: None,
        });
        runner.block_cases(
            &["HH-CLAW-003", "HH-CLAW-007"],
            "THEYOS_HH_POP_SIGNER_CMD missing",
        );

        assert_eq!(runner.report.count(CaseStatus::Blocked), 2);
        assert!(
            runner
                .report
                .cases
                .iter()
                .all(|case| case.status == CaseStatus::Blocked)
        );
    }

    #[test]
    fn query_token_boundary_requires_401_then_header_success() {
        assert_eq!(evaluate_query_token_boundary(401, true), CaseStatus::Pass);
        assert_eq!(evaluate_query_token_boundary(401, false), CaseStatus::Fail);
        assert_eq!(evaluate_query_token_boundary(200, true), CaseStatus::Fail);
    }

    #[test]
    fn signer_output_accepts_authorization_line_only() {
        assert_eq!(
            normalize_authorization_output("Authorization: Soyeht-PoP v1:test\n").as_deref(),
            Some("Soyeht-PoP v1:test")
        );
        assert!(normalize_authorization_output("Bearer nope").is_none());
    }
}
