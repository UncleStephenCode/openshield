use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use nix::fcntl::{Flock, FlockArg};
use nix::sys::socket::{getsockopt, sockopt::PeerCredentials};
use nix::sys::stat::{Mode as UnixMode, umask};
use nix::unistd::geteuid;

pub const RUNTIME_DIRECTORY: &str = "/run/openshield";
pub const INSTANCE_LOCK: &str = "/run/openshield/daemon.lock";
pub const CONTROL_SOCKET: &str = "/run/openshield/control.sock";
pub const OBSERVE_SOCKET: &str = "/run/openshield/observe.sock";

const RUNTIME_MODE: u32 = 0o755;
const LOCK_MODE: u32 = 0o600;
const CONTROL_MODE: u32 = 0o600;
const OBSERVE_MODE: u32 = 0o666;

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

    pub fn bind_sockets(self) -> Result<SocketSet> {
        ensure!(
            self.runtime_directory == Path::new(RUNTIME_DIRECTORY),
            "fixed socket paths require the fixed runtime directory"
        );
        bind_at(self, Path::new(CONTROL_SOCKET), Path::new(OBSERVE_SOCKET))
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
    _instance: DaemonInstance,
}

impl Drop for SocketSet {
    fn drop(&mut self) {
        remove_matching_socket(&self.control_path, self.owner_uid, self.control_identity);
        remove_matching_socket(&self.observe_path, self.owner_uid, self.observe_identity);
    }
}

pub fn peer_uid(stream: &UnixStream) -> Result<u32> {
    let credentials = getsockopt(stream, PeerCredentials).context("SO_PEERCRED failed")?;
    Ok(credentials.uid())
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

fn bind_at(
    instance: DaemonInstance,
    control_path: &Path,
    observe_path: &Path,
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
        set_socket_mode(control_path, CONTROL_MODE)?;
        set_socket_mode(observe_path, OBSERVE_MODE)?;
        verify_bound_socket(control_path, expected_uid, CONTROL_MODE, control_identity)?;
        verify_bound_socket(observe_path, expected_uid, OBSERVE_MODE, observe_identity)
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
        _instance: instance,
    })
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
    expected_uid: u32,
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
        metadata.uid() == expected_uid,
        "bound socket has an untrusted owner"
    );
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
    use nix::unistd::geteuid;
    use tempfile::tempdir;

    use super::{
        DaemonInstance, bind_at, bound_socket_identity, is_control_uid_authorized, peer_uid,
        prepare_socket_path, remove_matching_socket,
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

        let sockets = bind_at(acquire_test_instance(&runtime, uid)?, &control, &observe)?;
        assert_eq!(fs::symlink_metadata(&runtime)?.mode() & 0o777, 0o755);
        assert_eq!(
            fs::symlink_metadata(runtime.join("daemon.lock"))?.mode() & 0o777,
            0o600
        );
        assert_eq!(fs::symlink_metadata(&control)?.mode() & 0o777, 0o600);
        assert_eq!(fs::symlink_metadata(&observe)?.mode() & 0o777, 0o666);
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
        let sockets = bind_at(acquire_test_instance(&runtime, uid)?, &control, &observe)?;
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
        let sockets = bind_at(acquire_test_instance(&runtime, uid)?, &control, &observe)?;
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
            )
        });
        assert!(result.is_err());
        Ok(())
    }
}
