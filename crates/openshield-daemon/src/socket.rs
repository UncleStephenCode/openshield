use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::sys::stat::{Mode as UnixMode, umask};
use nix::unistd::{Gid, Group, chown, geteuid};
use openshield_protocol::OBSERVE_GROUP_NAME;

pub const RUNTIME_DIRECTORY: &str = "/run/openshield";
pub const INSTANCE_LOCK: &str = "/run/openshield/daemon.lock";
pub const CONTROL_SOCKET: &str = "/run/openshield/control.sock";
pub const OBSERVE_SOCKET: &str = "/run/openshield/observe.sock";

const RUNTIME_MODE: u32 = 0o755;
const LOCK_MODE: u32 = 0o600;
const CONTROL_MODE: u32 = 0o600;
const OBSERVE_MODE: u32 = 0o660;
const MAX_PROC_IDENTITY_BYTES: usize = 1024 * 1024;
const MAX_SUPPLEMENTARY_GROUPS: usize = 65_536;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub struct DaemonInstance {
    _lock: Flock<File>,
    runtime_directory: PathBuf,
    owner_uid: u32,
}

impl DaemonInstance {
    pub fn acquire_fixed() -> Result<Self> {
        ensure!(
            geteuid().is_root(),
            "openshield-daemon must run with effective uid 0"
        );
        Self::acquire_at(Path::new(RUNTIME_DIRECTORY), Path::new(INSTANCE_LOCK), 0)
    }

    pub(crate) fn acquire_at(
        runtime_directory: &Path,
        lock_path: &Path,
        expected_uid: u32,
    ) -> Result<Self> {
        ensure_runtime_directory(runtime_directory, expected_uid)?;
        ensure!(
            lock_path.parent() == Some(runtime_directory),
            "daemon lock must be inside the verified runtime directory"
        );

        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(LOCK_MODE)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
            .open(lock_path)
            .with_context(|| format!("cannot open daemon lock {}", lock_path.display()))?;
        verify_lock_file(&file, lock_path, expected_uid)?;
        let lock =
            Flock::lock(file, FlockArg::LockExclusiveNonblock).map_err(|(_file, error)| {
                anyhow::anyhow!(
                    "another OpenShield daemon operation holds {}: {error}",
                    lock_path.display()
                )
            })?;
        // Verify the pathname again after taking the lock. A lock on an
        // unlinked inode must never be accepted as the singleton authority.
        verify_lock_file(&lock, lock_path, expected_uid)?;

        Ok(Self {
            _lock: lock,
            runtime_directory: runtime_directory.to_path_buf(),
            owner_uid: expected_uid,
        })
    }

    pub fn bind_sockets(self, observer_gid: u32) -> Result<SocketSet> {
        ensure!(
            self.runtime_directory == Path::new(RUNTIME_DIRECTORY),
            "fixed socket paths require the fixed runtime directory"
        );
        bind_at(
            self,
            Path::new(CONTROL_SOCKET),
            Path::new(OBSERVE_SOCKET),
            observer_gid,
        )
    }
}

#[derive(Debug)]
pub struct SocketSet {
    pub control: UnixListener,
    pub observe: UnixListener,
    control_path: PathBuf,
    observe_path: PathBuf,
    control_identity: SocketIdentity,
    observe_identity: SocketIdentity,
    owner_uid: u32,
    observer_gid: u32,
    _instance: DaemonInstance,
}

impl Drop for SocketSet {
    fn drop(&mut self) {
        remove_matching_socket(&self.control_path, self.owner_uid, self.control_identity);
        remove_matching_socket(&self.observe_path, self.owner_uid, self.observe_identity);
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PeerIdentity {
    pid: i32,
    uid: u32,
    gid: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProcessCredentials {
    effective_uid: u32,
    effective_gid: u32,
    supplementary_groups: Vec<u32>,
}

pub fn required_observer_gid() -> Result<u32> {
    let group = Group::from_name(OBSERVE_GROUP_NAME)
        .with_context(|| format!("cannot resolve required group {OBSERVE_GROUP_NAME}"))?
        .ok_or_else(|| anyhow::anyhow!("required group {OBSERVE_GROUP_NAME} does not exist"))?;
    Ok(group.gid.as_raw())
}

fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity> {
    let credentials = getsockopt(stream, PeerCredentials).context("SO_PEERCRED failed")?;
    Ok(PeerIdentity {
        pid: credentials.pid(),
        uid: credentials.uid(),
        gid: credentials.gid(),
    })
}

pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    Ok(peer_identity(stream)?.uid)
}

pub fn authorize_control_peer(stream: &UnixStream) -> Result<()> {
    let uid = peer_uid(stream)?;
    ensure!(
        is_control_uid_authorized(uid),
        "control request denied for uid {uid}"
    );
    Ok(())
}

pub const fn is_control_uid_authorized(uid: u32) -> bool {
    uid == 0
}

pub fn authorize_observe_peer(stream: &UnixStream, observer_gid: u32) -> Result<u32> {
    let peer = peer_identity(stream)?;
    ensure!(
        observe_peer_is_authorized(peer, observer_gid, Path::new("/proc"))?,
        "observation request denied for uid {}",
        peer.uid
    );
    Ok(peer.uid)
}

fn observe_peer_is_authorized(
    peer: PeerIdentity,
    observer_gid: u32,
    proc_root: &Path,
) -> Result<bool> {
    if peer.uid == 0 || peer.gid == observer_gid {
        return Ok(true);
    }
    ensure!(peer.pid > 0, "observation peer has no usable process id");

    let process = proc_root.join(peer.pid.to_string());
    let start_before = read_process_start_time(&process)?;
    let first = read_process_credentials(&process)?;
    let second = read_process_credentials(&process)?;
    let start_after = read_process_start_time(&process)?;
    ensure!(
        start_before == start_after && first == second,
        "observation peer identity changed during authorization"
    );
    ensure!(
        first.effective_uid == peer.uid && first.effective_gid == peer.gid,
        "observation peer credentials no longer match SO_PEERCRED"
    );
    Ok(first.supplementary_groups.contains(&observer_gid))
}

fn read_process_start_time(process: &Path) -> Result<u64> {
    let text = read_bounded_text(&process.join("stat"))?;
    let command_end = text
        .rfind(')')
        .ok_or_else(|| anyhow::anyhow!("process stat has no command terminator"))?;
    let fields: Vec<&str> = text[command_end + 1..].split_ascii_whitespace().collect();
    // The suffix starts at field 3 (state); starttime is field 22.
    let start_time = fields
        .get(19)
        .ok_or_else(|| anyhow::anyhow!("process stat has no start time"))?;
    start_time
        .parse::<u64>()
        .context("process stat start time is invalid")
}

fn read_process_credentials(process: &Path) -> Result<ProcessCredentials> {
    let text = read_bounded_text(&process.join("status"))?;
    parse_process_credentials(&text)
}

fn read_bounded_text(path: &Path) -> Result<String> {
    let file = File::open(path)
        .with_context(|| format!("cannot open process identity file {}", path.display()))?;
    let limit =
        u64::try_from(MAX_PROC_IDENTITY_BYTES).context("process identity bound overflow")?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .with_context(|| format!("cannot read process identity file {}", path.display()))?;
    ensure!(
        bytes.len() <= MAX_PROC_IDENTITY_BYTES,
        "process identity file exceeds its byte bound"
    );
    String::from_utf8(bytes).context("process identity file is not UTF-8 ASCII")
}

fn parse_process_credentials(text: &str) -> Result<ProcessCredentials> {
    let mut effective_user = None;
    let mut effective_group = None;
    let mut supplementary_groups = None;
    for line in text.lines() {
        if let Some(values) = line.strip_prefix("Uid:") {
            effective_user = Some(parse_effective_id(values, "Uid")?);
        } else if let Some(values) = line.strip_prefix("Gid:") {
            effective_group = Some(parse_effective_id(values, "Gid")?);
        } else if let Some(values) = line.strip_prefix("Groups:") {
            let groups = values
                .split_ascii_whitespace()
                .map(str::parse::<u32>)
                .collect::<std::result::Result<Vec<_>, _>>()
                .context("process supplementary group list is invalid")?;
            ensure!(
                groups.len() <= MAX_SUPPLEMENTARY_GROUPS,
                "process supplementary group count exceeds its bound"
            );
            supplementary_groups = Some(groups);
        }
    }
    Ok(ProcessCredentials {
        effective_uid: effective_user
            .ok_or_else(|| anyhow::anyhow!("process status has no effective uid"))?,
        effective_gid: effective_group
            .ok_or_else(|| anyhow::anyhow!("process status has no effective gid"))?,
        supplementary_groups: supplementary_groups
            .ok_or_else(|| anyhow::anyhow!("process status has no supplementary groups"))?,
    })
}

fn parse_effective_id(values: &str, field: &str) -> Result<u32> {
    values
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| anyhow::anyhow!("process status {field} has no effective value"))?
        .parse::<u32>()
        .with_context(|| format!("process status {field} effective value is invalid"))
}

fn bind_at(
    instance: DaemonInstance,
    control_path: &Path,
    observe_path: &Path,
    observer_gid: u32,
) -> Result<SocketSet> {
    let expected_uid = instance.owner_uid;
    ensure!(
        control_path.parent() == Some(instance.runtime_directory.as_path())
            && observe_path.parent() == Some(instance.runtime_directory.as_path()),
        "management sockets must be inside the locked runtime directory"
    );
    prepare_socket_path(control_path, expected_uid)?;
    prepare_socket_path(observe_path, expected_uid)?;

    // Restrictive creation closes the interval between bind(2) and chmod(2).
    let previous_umask = umask(UnixMode::from_bits_truncate(0o077));
    let control_result = UnixListener::bind(control_path);
    let observe_result = if control_result.is_ok() {
        Some(UnixListener::bind(observe_path))
    } else {
        None
    };
    umask(previous_umask);

    let control = control_result
        .with_context(|| format!("cannot bind control socket {}", control_path.display()))?;
    let control_identity = bound_socket_identity(&control, control_path, expected_uid)
        .context("cannot identify the newly created control socket")?;
    let observe = match observe_result {
        Some(Ok(listener)) => listener,
        Some(Err(error)) => {
            remove_matching_socket(control_path, expected_uid, control_identity);
            return Err(error)
                .with_context(|| format!("cannot bind observe socket {}", observe_path.display()));
        }
        None => {
            remove_matching_socket(control_path, expected_uid, control_identity);
            return Err(anyhow::anyhow!("control socket was not created"));
        }
    };
    let observe_identity = match bound_socket_identity(&observe, observe_path, expected_uid) {
        Ok(identity) => identity,
        Err(error) => {
            remove_matching_socket(control_path, expected_uid, control_identity);
            return Err(error).context("cannot identify the newly created observe socket");
        }
    };

    let finalize = (|| -> Result<()> {
        set_socket_group(observe_path, expected_uid, observer_gid)?;
        set_socket_mode(control_path, CONTROL_MODE)?;
        set_socket_mode(observe_path, OBSERVE_MODE)?;
        verify_bound_socket(
            control_path,
            expected_uid,
            None,
            CONTROL_MODE,
            control_identity,
        )?;
        verify_bound_socket(
            observe_path,
            expected_uid,
            Some(observer_gid),
            OBSERVE_MODE,
            observe_identity,
        )
    })();
    if let Err(error) = finalize {
        remove_matching_socket(control_path, expected_uid, control_identity);
        remove_matching_socket(observe_path, expected_uid, observe_identity);
        return Err(error);
    }

    Ok(SocketSet {
        control,
        observe,
        control_path: control_path.to_path_buf(),
        observe_path: observe_path.to_path_buf(),
        control_identity,
        observe_identity,
        owner_uid: expected_uid,
        observer_gid,
        _instance: instance,
    })
}

impl SocketSet {
    pub const fn observer_gid(&self) -> u32 {
        self.observer_gid
    }
}

fn verify_lock_file(file: &File, path: &Path, expected_uid: u32) -> Result<()> {
    let descriptor = file
        .metadata()
        .with_context(|| format!("cannot inspect opened daemon lock {}", path.display()))?;
    let pathname = fs::symlink_metadata(path)
        .with_context(|| format!("cannot verify daemon lock path {}", path.display()))?;
    for metadata in [&descriptor, &pathname] {
        ensure!(metadata.is_file(), "daemon lock is not a regular file");
        ensure!(
            metadata.uid() == expected_uid,
            "daemon lock has an untrusted owner"
        );
        ensure!(
            metadata.mode() & 0o7777 == LOCK_MODE,
            "daemon lock must have mode {LOCK_MODE:#o}"
        );
        ensure!(
            metadata.nlink() == 1,
            "daemon lock must have exactly one hard link"
        );
    }
    ensure!(
        descriptor.dev() == pathname.dev() && descriptor.ino() == pathname.ino(),
        "daemon lock pathname changed while it was opened"
    );
    Ok(())
}

fn ensure_runtime_directory(path: &Path, expected_uid: u32) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            // Create privately first so an inherited permissive umask cannot
            // expose a writable directory before the final read-only mode.
            DirBuilder::new()
                .mode(0o700)
                .create(path)
                .with_context(|| format!("cannot create runtime directory {}", path.display()))?;
            fs::set_permissions(path, fs::Permissions::from_mode(RUNTIME_MODE)).with_context(
                || format!("cannot set runtime directory mode on {}", path.display()),
            )?;
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot inspect runtime directory {}", path.display()));
        }
    }

    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot verify runtime directory {}", path.display()))?;
    ensure!(
        !metadata.file_type().is_symlink(),
        "runtime directory is a symlink"
    );
    ensure!(metadata.is_dir(), "runtime path is not a directory");
    ensure!(
        metadata.uid() == expected_uid,
        "runtime directory has an untrusted owner"
    );
    let mode = metadata.mode() & 0o777;
    ensure!(
        mode == RUNTIME_MODE,
        "runtime directory must have mode {RUNTIME_MODE:#o}, not {mode:#o}"
    );
    Ok(())
}

fn prepare_socket_path(path: &Path, expected_uid: u32) -> Result<()> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => {
            return Err(error).with_context(|| format!("cannot inspect {}", path.display()));
        }
    };
    ensure!(
        !metadata.file_type().is_symlink(),
        "refusing socket-path symlink {}",
        path.display()
    );
    ensure!(
        metadata.uid() == expected_uid,
        "refusing non-root socket object {}",
        path.display()
    );
    ensure!(
        metadata.file_type().is_socket(),
        "refusing non-socket object {}",
        path.display()
    );
    let identity = SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    remove_matching_socket(path, expected_uid, identity);
    ensure!(
        fs::symlink_metadata(path).is_err_and(|error| error.kind() == io::ErrorKind::NotFound),
        "stale socket changed before it could be removed: {}",
        path.display()
    );
    Ok(())
}

fn set_socket_mode(path: &Path, mode: u32) -> Result<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(mode))
        .with_context(|| format!("cannot set permissions on {}", path.display()))
}

fn set_socket_group(path: &Path, expected_uid: u32, observer_gid: u32) -> Result<()> {
    // The verified runtime directory is root-owned and not writable by group
    // or others. The socket is still 0600 here, so changing its group cannot
    // expose an interval in which an untrusted user may connect.
    let before = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect group ownership on {}", path.display()))?;
    ensure!(
        before.file_type().is_socket() && before.uid() == expected_uid,
        "socket identity changed before its observation group was assigned"
    );
    // The systemd unit keeps root as the primary group and adds openshield as
    // a supplementary group. Linux permits an inode owner to select one of its
    // supplementary groups, so this narrow change does not require CAP_CHOWN.
    // Other init systems run the daemon as normal root and retain this path.
    if before.gid() != observer_gid {
        chown(path, None, Some(Gid::from_raw(observer_gid))).with_context(|| {
            format!(
                "cannot assign {} group ownership to {}",
                OBSERVE_GROUP_NAME,
                path.display()
            )
        })?;
    }
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot verify group ownership on {}", path.display()))?;
    ensure!(
        metadata.file_type().is_socket()
            && metadata.uid() == expected_uid
            && metadata.gid() == observer_gid,
        "socket identity changed while its observation group was assigned"
    );
    Ok(())
}

fn bound_socket_identity(
    listener: &UnixListener,
    path: &Path,
    expected_uid: u32,
) -> Result<SocketIdentity> {
    let address = listener
        .local_addr()
        .with_context(|| format!("cannot inspect bound listener {}", path.display()))?;
    ensure!(
        address.as_pathname() == Some(path),
        "listener is not bound to the expected pathname"
    );
    // AF_UNIX descriptor metadata belongs to sockfs on Linux and is not the
    // filesystem directory entry. Capture the pathname identity after bind;
    // the containing directory is verified and not writable by other users.
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot inspect bound socket {}", path.display()))?;
    ensure!(
        metadata.file_type().is_socket(),
        "bound path is not a socket"
    );
    ensure!(
        metadata.uid() == expected_uid,
        "bound socket has an untrusted owner"
    );
    Ok(SocketIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
    })
}

fn verify_bound_socket(
    path: &Path,
    required_owner: u32,
    required_group: Option<u32>,
    expected_mode: u32,
    identity: SocketIdentity,
) -> Result<()> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("cannot verify socket {}", path.display()))?;
    ensure!(
        metadata.file_type().is_socket(),
        "bound path is not a socket"
    );
    ensure!(
        metadata.uid() == required_owner,
        "bound socket has an untrusted owner"
    );
    if let Some(required_group) = required_group {
        ensure!(
            metadata.gid() == required_group,
            "bound socket has an untrusted group"
        );
    }
    ensure!(
        metadata.mode() & 0o777 == expected_mode,
        "bound socket has an unsafe mode"
    );
    ensure!(
        metadata.dev() == identity.device && metadata.ino() == identity.inode,
        "bound socket pathname changed during creation"
    );
    Ok(())
}

fn remove_matching_socket(path: &Path, expected_uid: u32, identity: SocketIdentity) {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return;
    };
    if metadata.uid() == expected_uid
        && metadata.file_type().is_socket()
        && metadata.dev() == identity.device
        && metadata.ino() == identity.inode
    {
        let _ignored = fs::remove_file(path);
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::Path;

    use anyhow::Result;
    use nix::unistd::{getegid, geteuid};
    use tempfile::tempdir;

    use super::{
        DaemonInstance, PeerIdentity, bind_at, bound_socket_identity, is_control_uid_authorized,
        observe_peer_is_authorized, parse_process_credentials, peer_uid, prepare_socket_path,
        remove_matching_socket,
    };

    fn acquire_test_instance(runtime: &Path, uid: u32) -> Result<DaemonInstance> {
        DaemonInstance::acquire_at(runtime, &runtime.join("daemon.lock"), uid)
    }

    #[test]
    fn creates_socket_pair_with_separate_permissions() -> Result<()> {
        let temporary = tempdir()?;
        let runtime = temporary.path().join("run");
        let control = runtime.join("control.sock");
        let observe = runtime.join("observe.sock");
        let uid = geteuid().as_raw();
        let gid = getegid().as_raw();

        let sockets = bind_at(
            acquire_test_instance(&runtime, uid)?,
            &control,
            &observe,
            gid,
        )?;
        assert_eq!(fs::symlink_metadata(&runtime)?.mode() & 0o777, 0o755);
        assert_eq!(
            fs::symlink_metadata(runtime.join("daemon.lock"))?.mode() & 0o777,
            0o600
        );
        assert_eq!(fs::symlink_metadata(&control)?.mode() & 0o777, 0o600);
        let observe_metadata = fs::symlink_metadata(&observe)?;
        assert_eq!(observe_metadata.mode() & 0o777, 0o660);
        assert_eq!(observe_metadata.gid(), gid);
        assert_eq!(sockets.observer_gid(), gid);
        drop(sockets);
        assert!(!control.exists());
        assert!(!observe.exists());
        assert!(runtime.join("daemon.lock").exists());
        Ok(())
    }

    #[test]
    fn singleton_lock_is_nonblocking_and_uses_a_persistent_inode() -> Result<()> {
        let temporary = tempdir()?;
        let runtime = temporary.path().join("run");
        let uid = geteuid().as_raw();

        let first = acquire_test_instance(&runtime, uid)?;
        assert!(acquire_test_instance(&runtime, uid).is_err());
        drop(first);
        assert!(runtime.join("daemon.lock").exists());
        let _replacement = acquire_test_instance(&runtime, uid)?;
        Ok(())
    }

    #[test]
    fn singleton_lock_refuses_symbolic_links() -> Result<()> {
        let temporary = tempdir()?;
        let runtime = temporary.path().join("run");
        let uid = geteuid().as_raw();
        let initial = acquire_test_instance(&runtime, uid)?;
        drop(initial);
        fs::remove_file(runtime.join("daemon.lock"))?;
        let target = temporary.path().join("target");
        fs::write(&target, b"unchanged")?;
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600))?;
        symlink(&target, runtime.join("daemon.lock"))?;

        assert!(acquire_test_instance(&runtime, uid).is_err());
        assert_eq!(fs::read(target)?, b"unchanged");
        Ok(())
    }

    #[test]
    fn second_instance_cannot_replace_bound_sockets() -> Result<()> {
        let temporary = tempdir()?;
        let runtime = temporary.path().join("run");
        let control = runtime.join("control.sock");
        let observe = runtime.join("observe.sock");
        let uid = geteuid().as_raw();
        let sockets = bind_at(
            acquire_test_instance(&runtime, uid)?,
            &control,
            &observe,
            getegid().as_raw(),
        )?;
        let control_identity = fs::symlink_metadata(&control)?;
        let observe_identity = fs::symlink_metadata(&observe)?;

        assert!(acquire_test_instance(&runtime, uid).is_err());
        let current_control = fs::symlink_metadata(&control)?;
        let current_observe = fs::symlink_metadata(&observe)?;
        assert_eq!(
            (current_control.dev(), current_control.ino()),
            (control_identity.dev(), control_identity.ino())
        );
        assert_eq!(
            (current_observe.dev(), current_observe.ino()),
            (observe_identity.dev(), observe_identity.ino())
        );
        drop(sockets);
        Ok(())
    }

    #[test]
    fn old_socket_set_drop_does_not_remove_replacement_socket() -> Result<()> {
        let temporary = tempdir()?;
        let runtime = temporary.path().join("run");
        let control = runtime.join("control.sock");
        let observe = runtime.join("observe.sock");
        let uid = geteuid().as_raw();
        let sockets = bind_at(
            acquire_test_instance(&runtime, uid)?,
            &control,
            &observe,
            getegid().as_raw(),
        )?;
        fs::remove_file(&control)?;
        let replacement = UnixListener::bind(&control)?;
        let replacement_identity = bound_socket_identity(&replacement, &control, uid)?;

        drop(sockets);
        let metadata = fs::symlink_metadata(&control)?;
        assert_eq!(
            (metadata.dev(), metadata.ino()),
            (replacement_identity.device, replacement_identity.inode)
        );
        assert!(!observe.exists());
        drop(replacement);
        remove_matching_socket(&control, uid, replacement_identity);
        Ok(())
    }

    #[test]
    fn refuses_regular_file_at_socket_path() -> Result<()> {
        let temporary = tempdir()?;
        let path = temporary.path().join("control.sock");
        fs::write(&path, b"do not delete")?;
        let result = prepare_socket_path(&path, fs::symlink_metadata(&path)?.uid());
        assert!(result.is_err());
        assert_eq!(fs::read(path)?, b"do not delete");
        Ok(())
    }

    #[test]
    fn peer_credentials_come_from_kernel() -> Result<()> {
        let (first, _second) = UnixStream::pair()?;
        assert_eq!(peer_uid(&first)?, geteuid().as_raw());
        assert!(is_control_uid_authorized(0));
        assert!(!is_control_uid_authorized(1_000));
        Ok(())
    }

    #[test]
    fn supplementary_observer_group_is_verified_against_stable_proc_identity() -> Result<()> {
        let temporary = tempdir()?;
        let process = temporary.path().join("4242");
        fs::create_dir(&process)?;
        fs::write(
            process.join("stat"),
            "4242 (observer worker) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20\n",
        )?;
        fs::write(
            process.join("status"),
            "Name:\tobserver\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\nGroups:\t4 991 1000\n",
        )?;
        let peer = PeerIdentity {
            pid: 4242,
            uid: 1000,
            gid: 1000,
        };

        assert!(observe_peer_is_authorized(peer, 991, temporary.path())?);
        assert!(!observe_peer_is_authorized(peer, 992, temporary.path())?);
        Ok(())
    }

    #[test]
    fn root_and_primary_group_observers_use_immutable_peer_credentials() -> Result<()> {
        let missing_proc = Path::new("/definitely/not/proc");
        assert!(observe_peer_is_authorized(
            PeerIdentity {
                pid: 1,
                uid: 0,
                gid: 0,
            },
            991,
            missing_proc,
        )?);
        assert!(observe_peer_is_authorized(
            PeerIdentity {
                pid: 42,
                uid: 1000,
                gid: 991,
            },
            991,
            missing_proc,
        )?);
        Ok(())
    }

    #[test]
    fn observer_authorization_rejects_proc_credentials_that_differ_from_peercred() -> Result<()> {
        let temporary = tempdir()?;
        let process = temporary.path().join("4242");
        fs::create_dir(&process)?;
        fs::write(
            process.join("stat"),
            "4242 (observer) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 424242 20\n",
        )?;
        fs::write(
            process.join("status"),
            "Uid:\t1001\t1001\t1001\t1001\nGid:\t1000\t1000\t1000\t1000\nGroups:\t991\n",
        )?;

        assert!(
            observe_peer_is_authorized(
                PeerIdentity {
                    pid: 4242,
                    uid: 1000,
                    gid: 1000,
                },
                991,
                temporary.path(),
            )
            .is_err()
        );
        Ok(())
    }

    #[test]
    fn process_group_parser_requires_all_credential_fields() -> Result<()> {
        let parsed = parse_process_credentials(
            "Uid:\t1000\t1001\t1002\t1003\nGid:\t2000\t2001\t2002\t2003\nGroups:\t10 20 30\n",
        )?;
        assert_eq!(parsed.effective_uid, 1001);
        assert_eq!(parsed.effective_gid, 2001);
        assert_eq!(parsed.supplementary_groups, [10, 20, 30]);
        assert!(parse_process_credentials("Uid:\t1\t1\t1\t1\n").is_err());
        Ok(())
    }

    #[test]
    fn runtime_directory_must_not_be_group_writable() -> Result<()> {
        let temporary = tempdir()?;
        let runtime = temporary.path().join("run");
        fs::create_dir(&runtime)?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o775))?;
        let uid = fs::symlink_metadata(&runtime)?.uid();
        let result = acquire_test_instance(&runtime, uid).and_then(|instance| {
            bind_at(
                instance,
                &runtime.join("control.sock"),
                &runtime.join("observe.sock"),
                getegid().as_raw(),
            )
        });
        assert!(result.is_err());
        Ok(())
    }

    #[test]
    fn runtime_directory_must_be_searchable_by_unprivileged_observers() -> Result<()> {
        let temporary = tempdir()?;
        let runtime = temporary.path().join("run");
        fs::create_dir(&runtime)?;
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700))?;
        let uid = fs::symlink_metadata(&runtime)?.uid();
        let result = acquire_test_instance(&runtime, uid).and_then(|instance| {
            bind_at(
                instance,
                &runtime.join("control.sock"),
                &runtime.join("observe.sock"),
                getegid().as_raw(),
            )
        });
        assert!(result.is_err());
        Ok(())
    }
}
