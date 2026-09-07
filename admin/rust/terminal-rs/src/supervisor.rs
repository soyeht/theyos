//! Independent owner of local PTYs. Disconnecting any client drops only its
//! transport; session ownership stays in this registry until explicit close.

use crate::pty::{LocalSpawnSpec, PtySession, start_supervised_session};
use crate::segmented_log::{LogLimits, ReplayRead, SegmentedLog};
use crate::supervisor_archives;
use crate::supervisor_intents::IntentStore;
use crate::supervisor_wire::{self as wire, Control, Frame, SessionInfo, SpawnRequest};
use fs2::FileExt;
use std::collections::{HashMap, HashSet};
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Semaphore;
use uuid::Uuid;

const MAX_SESSIONS: usize = 64;
const MAX_INTENTS: usize = 4096;
const MAX_CONNECTIONS: usize = 128;
const IO_TIMEOUT: Duration = Duration::from_secs(5);

struct Entry {
    conversation_id: String,
    instance_id: String,
    intent_id: String,
    session: Arc<PtySession>,
    log: Arc<SegmentedLog>,
}

impl Entry {
    fn info(&self) -> SessionInfo {
        let (cols, rows) = self.session.current_size();
        SessionInfo {
            conversation_id: self.conversation_id.clone(),
            session_instance_id: self.instance_id.clone(),
            intent_id: self.intent_id.clone(),
            slave_tty_path: self.session.slave_tty_path().to_owned(),
            pgid: self.session.pgid(),
            pid: self.session.child_pid(),
            cwd: self.session.cwd().to_string_lossy().into_owned(),
            cols,
            rows,
            closed: self.session.is_closed(),
        }
    }
}

struct Registry {
    sessions: HashMap<String, Arc<Entry>>,
    // Replaced closed instances may still be draining or serving final replay.
    // Their ownership and storage remain protected until both have finished.
    retiring: Vec<Arc<Entry>>,
    intents: HashMap<String, (String, String)>, // intent -> (request digest, conversation)
    tickets: IntentStore,
}

struct Broker {
    directory: PathBuf,
    boot_id: String,
    registry: Mutex<Registry>,
    // Keep exclusive ownership until all in-flight operations have finished,
    // including spawn_blocking work that cannot be cancelled by JoinSet.
    _owner: SocketOwner,
}

impl Drop for Broker {
    fn drop(&mut self) {
        let registry = self.registry.get_mut().unwrap_or_else(|e| e.into_inner());
        for entry in registry.sessions.values() {
            entry.session.close();
        }
        for entry in &registry.retiring {
            entry.session.close();
        }
    }
}

fn io_error(message: &str) -> io::Error {
    io::Error::other(message)
}

fn private_directory(path: &Path) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)?;
    let meta = fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no pointer arguments and cannot fail.
    #[allow(unsafe_code)]
    let uid = unsafe { libc::geteuid() };
    if !meta.is_dir() || meta.uid() != uid || meta.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PTY directory must be owned by this user and mode 0700",
        ));
    }
    Ok(())
}

fn exclusive_lock(path: &Path) -> io::Result<File> {
    // OpenOptions supplies O_CLOEXEC in addition to O_NOFOLLOW. Preserve it:
    // executed children must not inherit supervisor ownership locks.
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    FileExt::try_lock_exclusive(&file)?;
    Ok(file)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

impl Broker {
    fn prune_archives(&self, registry: &mut Registry) -> Result<(), &'static str> {
        registry.sessions.retain(|_, entry| {
            entry.session.completion().is_none() || Arc::strong_count(entry) > 1
        });
        registry
            .retiring
            .retain(|entry| entry.session.completion().is_none() || Arc::strong_count(entry) > 1);
        let protected = registry
            .sessions
            .values()
            .chain(registry.retiring.iter())
            .map(|entry| {
                self.directory
                    .join("sessions")
                    .join(&entry.conversation_id)
                    .join(&entry.instance_id)
            })
            .collect();
        supervisor_archives::prune(
            &self.directory.join("sessions"),
            &protected,
            supervisor_archives::MAX_ARCHIVED_BYTES,
            supervisor_archives::MAX_ARCHIVED_INSTANCES,
        )
        .map_err(|_| "storage_unavailable")
    }

    fn maintain(&self) -> Result<(), &'static str> {
        let mut registry = self.registry.lock().map_err(|_| "registry_unavailable")?;
        self.prune_archives(&mut registry)
    }

    fn create(&self, request: SpawnRequest) -> Result<(SessionInfo, bool), &'static str> {
        if !valid_id(&request.conversation_id)
            || Uuid::parse_str(&request.intent_id).is_err()
            || request.argv.is_empty()
            || request.argv.len() > 128
            || request.env.len() > 512
            || !Path::new(&request.cwd).is_absolute()
            || request.cols == 0
            || request.rows == 0
        {
            return Err("invalid_spawn");
        }
        let mut encoded = Vec::new();
        ciborium::into_writer(&request, &mut encoded).map_err(|_| "invalid_spawn")?;
        let digest = blake3::hash(&encoded).to_hex().to_string();
        let mut registry = self.registry.lock().map_err(|_| "registry_unavailable")?;
        if let Some((previous_digest, conversation)) = registry.intents.get(&request.intent_id) {
            if previous_digest != &digest {
                return Err("intent_mismatch");
            }
            return registry
                .sessions
                .get(conversation)
                .filter(|entry| entry.intent_id == request.intent_id && !entry.session.is_closed())
                .map(|entry| (entry.info(), true))
                .ok_or("intent_consumed");
        }
        registry
            .tickets
            .require_issued(&request.conversation_id, &request.intent_id)?;
        // Reclaim only completed, unobserved instances. Storage errors refuse
        // new execution but never terminate an existing session to meet budget.
        self.prune_archives(&mut registry)?;
        if registry
            .sessions
            .get(&request.conversation_id)
            .is_some_and(|entry| !entry.session.is_closed())
        {
            return Err("session_exists");
        }
        if registry.sessions.len() + registry.retiring.len() >= MAX_SESSIONS {
            return Err("session_limit");
        }
        registry
            .tickets
            .consume(&request.conversation_id, &request.intent_id)?;
        let instance_id = Uuid::new_v4().to_string();
        let path = self
            .directory
            .join("sessions")
            .join(&request.conversation_id)
            .join(&instance_id);
        let log = Arc::new(
            SegmentedLog::open(&path, LogLimits::default()).map_err(|_| "storage_unavailable")?,
        );
        let session = start_supervised_session(
            &LocalSpawnSpec {
                argv: request.argv,
                cwd: Some(PathBuf::from(request.cwd)),
                env: request.env,
            },
            &request.conversation_id,
            Arc::clone(&log),
            request.cols,
            request.rows,
        )
        .map_err(|_| "spawn_failed")?;
        let entry = Arc::new(Entry {
            conversation_id: request.conversation_id.clone(),
            instance_id,
            intent_id: request.intent_id.clone(),
            session,
            log,
        });
        let info = entry.info();
        registry
            .intents
            .insert(request.intent_id, (digest, request.conversation_id.clone()));
        if let Some(previous) = registry.sessions.insert(request.conversation_id, entry) {
            registry.retiring.push(previous);
        }
        Ok((info, false))
    }

    fn issue_intent(&self, conversation: &str) -> Result<String, &'static str> {
        if !valid_id(conversation) {
            return Err("invalid_spawn");
        }
        let mut registry = self.registry.lock().map_err(|_| "registry_unavailable")?;
        let protected: HashSet<_> = registry
            .sessions
            .values()
            .filter(|entry| !entry.session.is_closed())
            .map(|entry| entry.intent_id.clone())
            .collect();
        // Closed entries need no in-memory digest cache: their consumed disk
        // record (or its absence after GC) prevents every future execution.
        registry
            .intents
            .retain(|intent, _| protected.contains(intent));
        registry.tickets.issue(conversation, &protected)
    }

    fn lookup(&self, conversation: &str, instance: &str) -> Result<Arc<Entry>, &'static str> {
        let registry = self.registry.lock().map_err(|_| "registry_unavailable")?;
        let entry = registry
            .sessions
            .get(conversation)
            .ok_or("session_not_found")?;
        if entry.instance_id != instance {
            return Err("instance_mismatch");
        }
        Ok(Arc::clone(entry))
    }

    fn cancel_create(&self, conversation: &str, intent: &str) -> Result<(), &'static str> {
        if !valid_id(conversation) || Uuid::parse_str(intent).is_err() {
            return Err("invalid_spawn");
        }
        let mut registry = self.registry.lock().map_err(|_| "registry_unavailable")?;
        if let Some((_, owner)) = registry.intents.get(intent) {
            if owner != conversation {
                return Err("intent_mismatch");
            }
        }
        // Revoking the ticket also fences a CREATE which has not arrived.
        // Absence never grants new execution authority.
        registry.tickets.cancel(conversation, intent)?;
        if let Some(entry) = registry.sessions.get(conversation) {
            if entry.intent_id == intent {
                entry.session.close();
            }
        }
        Ok(())
    }

    fn close(&self, conversation: &str, instance: &str) -> Result<(), &'static str> {
        let registry = self.registry.lock().map_err(|_| "registry_unavailable")?;
        let entry = registry
            .sessions
            .get(conversation)
            .ok_or("session_not_found")?;
        if entry.instance_id != instance {
            return Err("instance_mismatch");
        }
        // Compare and close under the same registry lock. A new create can
        // replace only the closed entry; this operation never selects it later.
        entry.session.close();
        Ok(())
    }
}

struct SocketOwner {
    path: PathBuf,
    inode: u64,
    socket_lock: File,
    state_lock: File,
}

impl Drop for SocketOwner {
    fn drop(&mut self) {
        if fs::symlink_metadata(&self.path)
            .is_ok_and(|meta| meta.ino() == self.inode && meta.file_type().is_socket())
        {
            let _ = fs::remove_file(&self.path);
        }
        // A concurrent fork may briefly inherit the file description. Release
        // ownership explicitly rather than waiting for every duplicate to close.
        let _ = FileExt::unlock(&self.socket_lock);
        let _ = FileExt::unlock(&self.state_lock);
    }
}

/// Hosts only the PTY service; no engine, launchd mutations, stdin harness, or
/// child-owning `IpcClient` is involved. Caller owns process lifetime.
pub async fn serve(socket: &Path, directory: &Path) -> io::Result<()> {
    let socket_directory = socket
        .parent()
        .ok_or_else(|| io_error("socket requires parent"))?;
    private_directory(socket_directory)?;
    private_directory(directory)?;
    let state_lock = exclusive_lock(&directory.join(".broker.lock"))?;
    let socket_lock = exclusive_lock(&socket_directory.join(".socket.lock"))?;
    if let Ok(meta) = fs::symlink_metadata(socket) {
        if !meta.file_type().is_socket() || UnixStream::connect(socket).await.is_ok() {
            return Err(io_error("refusing to replace an occupied socket"));
        }
        fs::remove_file(socket)?;
    }
    private_directory(&directory.join("intents"))?;
    private_directory(&directory.join("sessions"))?;
    let tickets = IntentStore::open(&directory.join("intents"), MAX_INTENTS).map_err(io_error)?;
    let listener = UnixListener::bind(socket)?;
    fs::set_permissions(socket, fs::Permissions::from_mode(0o600))?;
    let owner = SocketOwner {
        path: socket.to_owned(),
        inode: fs::symlink_metadata(socket)?.ino(),
        socket_lock,
        state_lock,
    };
    let broker = Arc::new(Broker {
        _owner: owner,
        directory: directory.to_owned(),
        boot_id: Uuid::new_v4().to_string(),
        registry: Mutex::new(Registry {
            sessions: HashMap::new(),
            retiring: Vec::new(),
            intents: HashMap::new(),
            tickets,
        }),
    });
    let slots = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = tokio::task::JoinSet::new();
    // Maintenance is serial and owned by the service task. An idle broker
    // still collects completed logs; cancellation retains ownership until an
    // already-running blocking pass has finished.
    let mut maintenance = tokio::time::interval(Duration::from_secs(60));
    maintenance.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let mut maintenance_job = None;
    tracing::info!("ptyd.ready");
    loop {
        let accepted = tokio::select! {
            accepted = listener.accept() => accepted,
            _ = connections.join_next(), if !connections.is_empty() => continue,
            _ = maintenance.tick(), if maintenance_job.is_none() => {
                let broker = Arc::clone(&broker);
                maintenance_job = Some(tokio::task::spawn_blocking(move || broker.maintain()));
                continue;
            }
            result = async {
                match maintenance_job.as_mut() {
                    Some(job) => job.await,
                    None => std::future::pending().await,
                }
            },
                if maintenance_job.is_some() => {
                maintenance_job = None;
                if !matches!(result, Ok(Ok(()))) {
                    tracing::warn!("ptyd.archive.retention_failed");
                }
                continue;
            }
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            Err(error) => {
                tracing::warn!(kind = ?error.kind(), "ptyd.accept.unavailable");
                tokio::time::sleep(Duration::from_millis(250)).await;
                continue;
            }
        };
        let Ok(permit) = Arc::clone(&slots).try_acquire_owned() else {
            continue;
        };
        // Same-user access is the local execution boundary. The containing
        // directories and socket are private; remote auth remains in engine.
        #[allow(unsafe_code)] // SAFETY: geteuid has no pointer arguments.
        let uid = unsafe { libc::geteuid() };
        if !stream.peer_cred().is_ok_and(|peer| peer.uid() == uid) {
            continue;
        }
        let broker = Arc::clone(&broker);
        connections.spawn(async move {
            let _permit = permit;
            if let Err(error) = handle_connection(stream, broker).await {
                tracing::debug!(kind = ?error.kind(), "ptyd.transport.closed");
            }
        });
    }
}

async fn send(stream: &mut UnixStream, id: u64, message: Control) -> io::Result<()> {
    tokio::time::timeout(IO_TIMEOUT, wire::send_control(stream, id, message))
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "slow subscriber"))?
}

async fn handle_connection(mut stream: UnixStream, broker: Arc<Broker>) -> io::Result<()> {
    let frame = tokio::time::timeout(IO_TIMEOUT, wire::read_frame(&mut stream))
        .await
        .map_err(|_| io_error("hello timeout"))??;
    let Frame::Control {
        id,
        message: Control::Hello { supported_versions },
    } = frame
    else {
        return Err(io_error("hello required"));
    };
    if !supported_versions.contains(&wire::VERSION) {
        send(
            &mut stream,
            id,
            Control::Error {
                code: "version_mismatch".into(),
            },
        )
        .await?;
        return Ok(());
    }
    send(
        &mut stream,
        id,
        Control::Welcome {
            selected_version: wire::VERSION,
            broker_boot_id: broker.boot_id.clone(),
            max_frame: u32::try_from(wire::MAX_FRAME).map_err(|_| io_error("frame limit"))?,
        },
    )
    .await?;
    loop {
        let Frame::Control { id, message } = wire::read_frame(&mut stream).await? else {
            return Err(io_error("control required"));
        };
        let result = match message {
            Control::IssueIntent { conversation_id } => {
                let broker = Arc::clone(&broker);
                tokio::task::spawn_blocking(move || {
                    broker
                        .issue_intent(&conversation_id)
                        .map(|intent_id| Control::IntentIssued {
                            intent_id,
                            conversation_id,
                        })
                })
                .await
                .map_err(|_| io_error("intent worker failed"))?
            }
            Control::Create { request } => {
                let broker = Arc::clone(&broker);
                tokio::task::spawn_blocking(move || broker.create(request))
                    .await
                    .map_err(|_| io_error("create worker failed"))?
                    .map(|(info, reconnected)| Control::Created { info, reconnected })
            }
            Control::Get { conversation_id } => broker
                .registry
                .lock()
                .map_err(|_| "registry_unavailable")
                .and_then(|registry| {
                    registry
                        .sessions
                        .get(&conversation_id)
                        .map(|entry| Control::Session { info: entry.info() })
                        .ok_or("session_not_found")
                }),
            Control::List => broker
                .registry
                .lock()
                .map_err(|_| "registry_unavailable")
                .map(|registry| Control::Sessions {
                    sessions: registry
                        .sessions
                        .values()
                        .map(|entry| entry.info())
                        .collect(),
                }),
            Control::Close {
                conversation_id,
                session_instance_id,
            } => broker
                .close(&conversation_id, &session_instance_id)
                .map(|()| Control::Ok),
            Control::CancelCreate {
                conversation_id,
                intent_id,
            } => {
                let broker = Arc::clone(&broker);
                tokio::task::spawn_blocking(move || {
                    broker.cancel_create(&conversation_id, &intent_id)
                })
                .await
                .map_err(|_| io_error("cancel worker failed"))?
                .map(|()| Control::Ok)
            }
            Control::Resize {
                conversation_id,
                session_instance_id,
                cols,
                rows,
            } => {
                if cols == 0 || rows == 0 {
                    Err("invalid_size")
                } else {
                    broker
                        .lookup(&conversation_id, &session_instance_id)
                        .and_then(|entry| {
                            if entry.session.is_closed() {
                                return Err("session_closed");
                            }
                            entry
                                .session
                                .resize(cols, rows)
                                .map(|()| Control::Ok)
                                .map_err(|_| "resize_failed")
                        })
                }
            }
            Control::Write {
                conversation_id,
                session_instance_id,
                bytes,
            } => match broker.lookup(&conversation_id, &session_instance_id) {
                Ok(entry) if bytes.len() <= 64 * 1024 => entry
                    .session
                    .write(&bytes)
                    .await
                    .map(|()| Control::Ok)
                    .map_err(|_| "write_failed"),
                Ok(_) => Err("input_too_large"),
                Err(code) => Err(code),
            },
            Control::Attach {
                conversation_id,
                session_instance_id,
                next_offset,
            } => match broker.lookup(&conversation_id, &session_instance_id) {
                Ok(entry) => return stream_session(&mut stream, id, entry, next_offset).await,
                Err(code) => Err(code),
            },
            _ => Err("unexpected_control"),
        };
        let message = result.unwrap_or_else(|code| Control::Error { code: code.into() });
        send(&mut stream, id, message).await?;
    }
}

async fn stream_session(
    stream: &mut UnixStream,
    id: u64,
    entry: Arc<Entry>,
    mut cursor: u64,
) -> io::Result<()> {
    let mut receiver = entry.session.subscribe();
    let (base, watermark) = entry.log.bounds()?;
    if cursor > watermark {
        return send(
            stream,
            id,
            Control::Error {
                code: "cursor_ahead".into(),
            },
        )
        .await;
    }
    send(
        stream,
        id,
        Control::Attached {
            info: entry.info(),
            base_offset: base,
            replay_end: watermark,
        },
    )
    .await?;
    while cursor < watermark {
        let count = usize::try_from((watermark - cursor).min(64 * 1024))
            .map_err(|_| io_error("replay limit"))?;
        let log = Arc::clone(&entry.log);
        let read = tokio::task::spawn_blocking(move || log.read(cursor, count))
            .await
            .map_err(|_| io_error("replay worker failed"))??;
        match read {
            ReplayRead::Gap {
                from,
                to,
                end_offset,
            } => {
                if to > watermark {
                    return send(
                        stream,
                        id,
                        Control::ResyncRequired {
                            base_offset: to,
                            end_offset,
                            reason: "retention_advanced".into(),
                        },
                    )
                    .await;
                }
                send(
                    stream,
                    id,
                    Control::Gap {
                        from,
                        to,
                        reason: "retention".into(),
                    },
                )
                .await?;
                cursor = to;
            }
            ReplayRead::Data(chunk) => {
                if chunk.bytes.is_empty() {
                    return Err(io_error("replay made no progress"));
                }
                cursor += chunk.bytes.len() as u64;
                send_output(stream, id, chunk.start_offset, chunk.bytes).await?;
            }
        }
    }
    send(stream, id, Control::ReplayEnd { offset: watermark }).await?;
    let mut tick = tokio::time::interval(Duration::from_millis(100));
    loop {
        if let Some(completion) = entry.session.completion() {
            let (_, end) = entry.log.bounds()?;
            if cursor >= end {
                return send(
                    stream,
                    id,
                    Control::Exit {
                        session_instance_id: entry.instance_id.clone(),
                        final_offset: end,
                        exit_code: completion.exit_code,
                        reason: if completion.log_write_failed {
                            "log_write_failed"
                        } else {
                            "process_ended"
                        }
                        .into(),
                    },
                )
                .await;
            }
        }
        let event = tokio::select! {
            result = receiver.recv() => result,
            _ = tick.tick() => continue,
            _ = stream.read_u8() => return Ok(()), // attach is output-only; EOF never closes the PTY.
        };
        match event {
            Ok((end, bytes)) => {
                if end <= cursor {
                    continue;
                }
                let start = end - bytes.len() as u64;
                if start > cursor {
                    return resync(stream, id, &entry).await;
                }
                let skip = usize::try_from(cursor - start).map_err(|_| io_error("live offset"))?;
                send_output(stream, id, cursor, bytes[skip..].to_vec()).await?;
                cursor = end;
            }
            Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                return resync(stream, id, &entry).await;
            }
            Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                return Err(io_error("output stream unavailable"));
            }
        }
    }
}

async fn resync(stream: &mut UnixStream, id: u64, entry: &Entry) -> io::Result<()> {
    let (base_offset, end_offset) = entry.log.bounds()?;
    send(
        stream,
        id,
        Control::ResyncRequired {
            base_offset,
            end_offset,
            reason: "subscriber_lagged".into(),
        },
    )
    .await
}

async fn send_output(
    stream: &mut UnixStream,
    id: u64,
    start_offset: u64,
    bytes: Vec<u8>,
) -> io::Result<()> {
    tokio::time::timeout(
        IO_TIMEOUT,
        wire::write_frame(
            stream,
            &Frame::Data {
                id,
                start_offset,
                bytes,
            },
        ),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "slow subscriber"))?
}
