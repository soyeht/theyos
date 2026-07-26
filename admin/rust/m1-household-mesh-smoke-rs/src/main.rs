mod adapters;
mod runner;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::{ExitCode, Termination};

use adapters::ProductionServices;
use clap::error::ErrorKind;
use clap::{Arg, Command};
use runner::{ActiveMode, Role};

const EXIT_USAGE: u8 = 2;

enum CliAction {
    Plan,
    Active {
        mode: ActiveMode,
        role: Role,
        acknowledged_dev_only: bool,
    },
    StaticOutput(String),
}

fn command() -> Command {
    let role = || {
        Arg::new("role")
            .long("role")
            .required(true)
            .value_parser(["mac", "linux"])
    };

    Command::new("m1-household-mesh-smoke")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Dev-only, read-only household mesh diagnostic smoke")
        .disable_help_subcommand(true)
        .subcommand(Command::new("preflight").arg(role()))
        .subcommand(
            Command::new("verify").arg(role()).arg(
                Arg::new("ack-dev-only")
                    .long("ack-dev-only")
                    .action(clap::ArgAction::SetTrue),
            ),
        )
}

fn parse_args<I, T>(args: I) -> Result<CliAction, ()>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let matches = match command().try_get_matches_from(args) {
        Ok(matches) => matches,
        Err(error) => {
            return match error.kind() {
                ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
                    Ok(CliAction::StaticOutput(error.render().to_string()))
                }
                _ => Err(()),
            };
        }
    };

    let Some((name, subcommand)) = matches.subcommand() else {
        return Ok(CliAction::Plan);
    };
    let role = match subcommand.get_one::<String>("role").map(String::as_str) {
        Some("mac") => Role::Mac,
        Some("linux") => Role::Linux,
        _ => return Err(()),
    };
    let mode = match name {
        "preflight" => ActiveMode::Preflight,
        "verify" => ActiveMode::Verify,
        _ => return Err(()),
    };
    let acknowledged_dev_only = name == "verify" && subcommand.get_flag("ack-dev-only");
    Ok(CliAction::Active {
        mode,
        role,
        acknowledged_dev_only,
    })
}

fn dispatch<W, F>(action: CliAction, output: &mut W, services: F) -> u8
where
    W: Write,
    F: FnOnce() -> ProductionServices,
{
    let result = match action {
        CliAction::Plan => output
            .write_all(runner::DRY_RUN_PLAN.as_bytes())
            .map(|()| 0),
        CliAction::StaticOutput(text) => output.write_all(text.as_bytes()).map(|()| 0),
        CliAction::Active {
            mode,
            role,
            acknowledged_dev_only,
        } => {
            if mode == ActiveMode::Verify && !acknowledged_dev_only {
                runner::report_missing_dev_ack(role, output)
            } else {
                let mut services = services();
                runner::run_active(mode, role, &mut services, output)
            }
        }
    };
    result.unwrap_or(runner::EXIT_FAIL)
}

fn main() -> impl Termination {
    let Ok(action) = parse_args(std::env::args_os()) else {
        eprintln!("error: invalid command line; use --help");
        return ExitCode::from(EXIT_USAGE);
    };

    ExitCode::from(dispatch(
        action,
        &mut io::stdout().lock(),
        ProductionServices::new,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingWriter;

    impl Write for FailingWriter {
        fn write(&mut self, _buffer: &[u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fixture refuses evidence",
            ))
        }

        fn flush(&mut self) -> io::Result<()> {
            Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "fixture refuses evidence",
            ))
        }
    }

    #[test]
    fn bare_invocation_returns_before_constructing_services() {
        let mut output = Vec::new();
        let code = dispatch(CliAction::Plan, &mut output, || -> ProductionServices {
            panic!("bare invocation must not construct adapters")
        });
        assert_eq!(code, 0);
        let text = String::from_utf8(output).expect("plan is UTF-8");
        assert!(text.contains("DRY RUN"));
        assert!(text.contains("no network requests"));
    }

    #[test]
    fn invalid_command_line_never_echoes_the_invalid_value() {
        let sensitive = "do-not-repeat-this-value";
        let result = parse_args(["smoke", "verify", "--role", sensitive]);
        assert!(result.is_err());
        let static_error = "error: invalid command line; use --help";
        assert!(!static_error.contains(sensitive));
    }

    #[test]
    fn active_commands_parse_to_closed_modes_and_roles() {
        assert!(matches!(
            parse_args(["smoke", "preflight", "--role", "mac"]),
            Ok(CliAction::Active {
                mode: ActiveMode::Preflight,
                role: Role::Mac,
                acknowledged_dev_only: false
            })
        ));
        assert!(matches!(
            parse_args(["smoke", "verify", "--role", "linux", "--ack-dev-only"]),
            Ok(CliAction::Active {
                mode: ActiveMode::Verify,
                role: Role::Linux,
                acknowledged_dev_only: true
            })
        ));
    }

    #[test]
    fn missing_verify_ack_blocks_before_constructing_services() {
        let mut output = Vec::new();
        let action = parse_args(["smoke", "verify", "--role", "linux"]).expect("valid CLI");
        let code = dispatch(action, &mut output, || -> ProductionServices {
            panic!("missing acknowledgement must stop before adapters")
        });
        assert_eq!(code, 20);
        assert!(
            String::from_utf8(output)
                .expect("report")
                .contains("BLOCKED M1-DEV-ACK")
        );
    }

    #[test]
    fn ack_is_rejected_outside_verify_without_echoing_user_input() {
        for args in [
            vec!["smoke", "--ack-dev-only"],
            vec!["smoke", "preflight", "--role", "mac", "--ack-dev-only"],
        ] {
            assert!(parse_args(args).is_err());
        }
    }

    #[test]
    fn evidence_write_failure_is_never_reported_as_success() {
        let actions = [
            parse_args(["smoke"]).expect("plan"),
            parse_args(["smoke", "--help"]).expect("static help"),
            parse_args(["smoke", "verify", "--role", "linux"]).expect("active"),
        ];
        for action in actions {
            let code = dispatch(action, &mut FailingWriter, || -> ProductionServices {
                panic!("write failure must stop before adapters")
            });
            assert_eq!(code, runner::EXIT_FAIL);
        }
    }
}
