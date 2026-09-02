use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{ErrorKind, Read};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::ops::Deref;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail, ensure};
use openshield_core::{
    ApplicationIdentity, ApplicationPath, CgroupPath, CommandArgument, ExecutableFileId,
    InterfaceName, MAX_COMMAND_ARGUMENTS, MAX_COMMAND_LINE_BYTES, Rule, RuleSpec, Snapshot,
    TransportProtocol,
};

const MAX_PROC_ENTRIES: usize = 131_072;
const MAX_FDS_PER_TASK: usize = 4_096;
const MAX_SOCKET_TABLE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STATUS_BYTES: usize = 256 * 1024;
const MAX_STAT_BYTES: usize = 64 * 1024;
const MAX_CGROUP_BYTES: usize = 256 * 1024;
const PROC_SCAN_DEADLINE: Duration = Duration::from_millis(250);

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct OutboundConnection {
    pub source_address: IpAddr,
    pub source_port: Option<u16>,
    pub destination_address: IpAddr,
    pub destination_port: Option<u16>,
    pub protocol: TransportProtocol,
    pub output_interface: InterfaceName,
    pub socket_uid: u32,
}

impl OutboundConnection {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.source_address.is_ipv4() == self.destination_address.is_ipv4(),
            "connection address families differ"
        );
        match self.protocol {
            TransportProtocol::Tcp | TransportProtocol::Udp => ensure!(
                self.source_port.is_some() && self.destination_port.is_some(),
                "transport connection has no ports"
            ),
            TransportProtocol::Icmp => ensure!(
                self.source_address.is_ipv4()
                    && self.source_port.is_some()
                    && self.destination_port.is_none(),
                "invalid ICMP echo connection tuple"
            ),
            TransportProtocol::IcmpV6 => ensure!(
                self.source_address.is_ipv6()
                    && self.source_port.is_some()
                    && self.destination_port.is_none(),
                "invalid ICMPv6 echo connection tuple"
            ),
            TransportProtocol::Any => bail!("untyped outbound connection cannot be attributed"),
        }
        Ok(())
    }
}

/// Resolves a manually supplied executable path to the exact file identity
/// persisted in policy state. Canonicalization and a stable pair of opened-file
/// snapshots bind the rule to the executable version visible in the daemon's
/// mount namespace.
pub fn pin_rule_application(specification: &mut RuleSpec) -> Result<()> {
    let Some(selector) = specification.application.as_mut() else {
        return Ok(());
    };
    let executable = selector
        .executable
        .as_ref()
        .ok_or_else(|| anyhow!("application selector has no executable path"))?;
    let executable_path = Path::new(executable.as_str());
    let canonical_path = fs::canonicalize(executable_path).with_context(|| {
        format!(
            "cannot canonicalize executable {}",
            executable_path.display()
        )
    })?;
    let (first_handle, actual_file) = open_executable_version(&canonical_path)?;
    let verified_canonical_path = fs::canonicalize(executable_path).with_context(|| {
        format!(
            "cannot re-canonicalize executable {}",
            executable_path.display()
        )
    })?;
    ensure!(
        verified_canonical_path == canonical_path,
        "executable path changed while it was pinned"
    );
    let (verification_handle, verified_file) = open_executable_version(&verified_canonical_path)?;
    ensure!(
        verified_file == actual_file,
        "executable version changed while it was pinned"
    );
    let final_canonical_path = fs::canonicalize(executable_path).with_context(|| {
        format!(
            "cannot finally canonicalize executable {}",
            executable_path.display()
        )
    })?;
    ensure!(
        final_canonical_path == canonical_path,
        "executable path changed while it was pinned"
    );
    let canonical_text = canonical_path
        .to_str()
        .ok_or_else(|| anyhow!("canonical executable path is not UTF-8"))?;
    let canonical_application = ApplicationPath::new(canonical_text.to_owned())?;
    if let Some(expected_file) = selector.executable_file {
        ensure!(
            expected_file == actual_file,
            "supplied executable version does not match the opened path"
        );
    }
    selector.executable = Some(canonical_application);
    selector.executable_file = Some(actual_file);
    specification.validate()?;
    drop((first_handle, verification_handle));
    Ok(())
}

fn open_executable_version(path: &Path) -> Result<(File, ExecutableFileId)> {
    let handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("cannot open executable {}", path.display()))?;
    let metadata = handle
        .metadata()
        .context("cannot inspect executable file")?;
    let identity = executable_file_id(&metadata)?;
    Ok((handle, identity))
}

fn executable_file_id(metadata: &Metadata) -> Result<ExecutableFileId> {
    ensure!(
        metadata.is_file(),
        "application executable is not a regular file"
    );
    let identity = ExecutableFileId {
        device: metadata.dev(),
        inode: metadata.ino(),
        size: metadata.size(),
        ctime_seconds: metadata.ctime(),
        ctime_nanoseconds: metadata.ctime_nsec(),
    };
    identity.validate()?;
    Ok(identity)
}

#[must_use]
#[cfg(test)]
pub fn matching_application_rule<'a>(
    snapshot: &'a Snapshot,
    connection: &OutboundConnection,
    identity: &ApplicationIdentity,
) -> Option<&'a Rule> {
    snapshot
        .rules
        .iter()
        .find(|rule| application_rule_matches(rule, connection, identity))
}

/// Immutable, indexed subset of policy used by the NFQUEUE decision path.
///
/// Every persisted application rule has a mandatory executable version pin.
/// Indexing on that pin prevents an unprivileged packet stream from forcing a
/// scan of all application rules. Rules for the same executable are still
/// evaluated in policy order so matching semantics remain unchanged.
#[derive(Clone, Debug)]
pub struct ApplicationDecisionPolicy {
    snapshot: Snapshot,
    rules_by_executable: HashMap<ExecutableFileId, Vec<usize>>,
}

impl ApplicationDecisionPolicy {
    #[must_use]
    pub fn new(snapshot: Snapshot) -> Self {
        let mut rules_by_executable = HashMap::<ExecutableFileId, Vec<usize>>::new();
        for (index, rule) in snapshot.rules.iter().enumerate() {
            let Some(file) = rule
                .spec
                .application
                .as_ref()
                .and_then(|selector| selector.executable_file)
            else {
                // State validation rejects unpinned application rules. If an
                // internal caller violates that invariant, omitting the rule
                // from the decision index is fail-closed.
                continue;
            };
            rules_by_executable.entry(file).or_default().push(index);
        }
        Self {
            snapshot,
            rules_by_executable,
        }
    }

    #[must_use]
    pub fn matching_rule(
        &self,
        connection: &OutboundConnection,
        identity: &ApplicationIdentity,
    ) -> Option<&Rule> {
        self.rules_by_executable
            .get(&identity.executable_file)?
            .iter()
            .filter_map(|index| self.snapshot.rules.get(*index))
            .find(|rule| application_rule_matches(rule, connection, identity))
    }

    #[must_use]
    pub fn rule_count(&self) -> usize {
        self.snapshot.rules.len()
    }

    #[cfg(test)]
    fn candidate_count(&self, file: ExecutableFileId) -> usize {
        self.rules_by_executable.get(&file).map_or(0, Vec::len)
    }
}

impl Deref for ApplicationDecisionPolicy {
    type Target = Snapshot;

    fn deref(&self) -> &Self::Target {
        &self.snapshot
    }
}

fn application_rule_matches(
    rule: &Rule,
    connection: &OutboundConnection,
    identity: &ApplicationIdentity,
) -> bool {
    rule.spec.enabled
        && rule.spec.direction == openshield_core::Direction::Outbound
        && rule
            .spec
            .application
            .as_ref()
            .is_some_and(|selector| selector.matches(identity))
        && (rule.spec.protocol == TransportProtocol::Any
            || rule.spec.protocol == connection.protocol)
        && rule
            .spec
            .peer_network
            .is_none_or(|network| network.contains(&connection.destination_address))
        && rule.spec.port.is_none_or(|range| {
            connection
                .destination_port
                .is_some_and(|port| port >= range.start() && port <= range.end())
        })
        && rule
            .spec
            .interface
            .as_ref()
            .is_none_or(|interface| interface == &connection.output_interface)
}

#[derive(Clone, Debug)]
pub struct ProcfsResolver {
    root: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct OwnerTask {
    tid: u32,
    path: PathBuf,
}

impl Default for ProcfsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ProcfsResolver {
    #[must_use]
    pub fn new() -> Self {
        Self {
            root: PathBuf::from("/proc"),
        }
    }

    #[cfg(test)]
    #[must_use]
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn resolve(&self, connection: &OutboundConnection) -> Result<ApplicationIdentity> {
        connection.validate()?;
        let deadline = Instant::now() + PROC_SCAN_DEADLINE;
        let inode = self.resolve_socket_inode(connection, deadline)?;
        let owners = self.resolve_unique_process_tasks(
            inode,
            connection.socket_uid,
            deadline,
            MAX_FDS_PER_TASK,
        )?;
        let mut identities = owners
            .into_iter()
            .map(|owner| {
                Self::capture_identity(
                    &owner.path,
                    owner.tid,
                    inode,
                    connection.socket_uid,
                    deadline,
                )
            })
            .collect::<Result<Vec<_>>>()?;
        let identity = identities
            .pop()
            .ok_or_else(|| anyhow!("attributed process has no socket-owning task"))?;
        ensure!(
            identities
                .iter()
                .all(|other| equivalent_enforcement_identity(other, &identity)),
            "socket-owning tasks have ambiguous application identities"
        );
        Ok(identity)
    }

    fn resolve_socket_inode(
        &self,
        connection: &OutboundConnection,
        deadline: Instant,
    ) -> Result<u64> {
        let table_name = match (connection.protocol, connection.source_address) {
            (TransportProtocol::Tcp, IpAddr::V4(_)) => "tcp",
            (TransportProtocol::Tcp, IpAddr::V6(_)) => "tcp6",
            (TransportProtocol::Udp, IpAddr::V4(_)) => "udp",
            (TransportProtocol::Udp, IpAddr::V6(_)) => "udp6",
            (TransportProtocol::Icmp, IpAddr::V4(_)) => "icmp",
            (TransportProtocol::IcmpV6, IpAddr::V6(_)) => "icmp6",
            _ => bail!("unsupported protocol/address-family combination"),
        };
        let table = read_bounded(
            &self.root.join("self").join("net").join(table_name),
            MAX_SOCKET_TABLE_BYTES,
            deadline,
        )
        .with_context(|| format!("cannot read /proc/self/net/{table_name}"))?;
        let text = std::str::from_utf8(&table).context("socket table is not UTF-8 ASCII")?;
        let mut candidates = BTreeSet::new();
        for (index, line) in text.lines().skip(1).enumerate() {
            ensure_within_deadline(deadline)?;
            ensure!(
                index < MAX_PROC_ENTRIES,
                "socket table entry bound exceeded"
            );
            if let Some(candidate) = parse_socket_line(line)?
                && candidate.uid == connection.socket_uid
                && candidate.matches(connection)
            {
                candidates.insert(candidate.inode);
            }
        }
        ensure!(
            candidates.len() == 1,
            "socket attribution is missing or ambiguous"
        );
        ensure_within_deadline(deadline)?;
        candidates
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("socket attribution disappeared"))
    }

    fn resolve_unique_process_tasks(
        &self,
        inode: u64,
        uid: u32,
        deadline: Instant,
        maximum_fds: usize,
    ) -> Result<Vec<OwnerTask>> {
        ensure!(maximum_fds > 0, "per-task fd bound is zero");
        let target = format!("socket:[{inode}]");
        let process_ids = enumerate_process_ids(&self.root, deadline)?;
        let mut owners: BTreeMap<u32, Vec<OwnerTask>> = BTreeMap::new();
        let mut task_count = 0_usize;
        for process_id in process_ids {
            ensure_within_deadline(deadline)?;
            let process = self.root.join(process_id.to_string());
            let task_root = process.join("task");
            let Some(task_ids) =
                enumerate_task_ids(&process, &task_root, process_id, deadline, &mut task_count)?
            else {
                continue;
            };
            for tid in task_ids {
                ensure_within_deadline(deadline)?;
                let task = task_root.join(tid.to_string());
                if task_owns_socket(&task, process_id, tid, &target, uid, deadline, maximum_fds)? {
                    owners
                        .entry(process_id)
                        .or_default()
                        .push(OwnerTask { tid, path: task });
                }
            }
            ensure!(
                owners.len() <= 1,
                "socket is shared by multiple processes; attribution is ambiguous"
            );
        }
        ensure_within_deadline(deadline)?;
        owners
            .into_iter()
            .next()
            .map(|(_tgid, tasks)| tasks)
            .ok_or_else(|| anyhow!("no process owns the attributed socket inode"))
    }

    fn capture_identity(
        process: &Path,
        pid: u32,
        inode: u64,
        expected_uid: u32,
        deadline: Instant,
    ) -> Result<ApplicationIdentity> {
        let socket_target = format!("socket:[{inode}]");
        let fd_path = find_socket_fd(process, &socket_target, deadline)?;
        let start_before = read_start_time(process, deadline)?;
        let uid_before = read_process_fs_uid(process, deadline)?;
        ensure!(uid_before == expected_uid, "process/socket uid mismatch");

        ensure_within_deadline(deadline)?;
        let executable_link_before =
            fs::read_link(process.join("exe")).context("cannot read process executable link")?;
        ensure_within_deadline(deadline)?;
        let executable_text = executable_link_before
            .to_str()
            .ok_or_else(|| anyhow!("process executable path is not UTF-8"))?;
        let executable = ApplicationPath::new(executable_text.to_owned())?;
        let executable_handle =
            File::open(process.join("exe")).context("cannot pin process executable")?;
        ensure_within_deadline(deadline)?;
        let executable_metadata = executable_handle
            .metadata()
            .context("cannot inspect pinned process executable")?;
        ensure_within_deadline(deadline)?;
        let executable_file = executable_file_id(&executable_metadata)
            .context("cannot identify pinned process executable version")?;

        let command_line = read_command_line(process, deadline)?;
        let cgroups = read_cgroups(process, deadline)?;

        ensure_within_deadline(deadline)?;
        let executable_link_after =
            fs::read_link(process.join("exe")).context("cannot re-read process executable link")?;
        ensure_within_deadline(deadline)?;
        let executable_after_metadata = File::open(process.join("exe"))
            .context("cannot re-pin process executable")?
            .metadata()
            .context("cannot re-inspect process executable")?;
        let executable_file_after = executable_file_id(&executable_after_metadata)
            .context("cannot re-identify pinned process executable version")?;
        ensure_within_deadline(deadline)?;
        let command_line_after = read_command_line(process, deadline)?;
        let cgroups_after = read_cgroups(process, deadline)?;
        let start_after = read_start_time(process, deadline)?;
        let uid_after = read_process_fs_uid(process, deadline)?;
        ensure!(
            executable_link_before == executable_link_after
                && executable_file == executable_file_after
                && command_line == command_line_after
                && cgroups == cgroups_after
                && start_before == start_after
                && uid_before == uid_after,
            "process identity changed while it was captured"
        );
        ensure_within_deadline(deadline)?;
        let final_socket_link = fs::read_link(&fd_path)
            .ok()
            .and_then(|link| link.to_str().map(ToOwned::to_owned));
        ensure_within_deadline(deadline)?;
        ensure!(
            final_socket_link.as_deref() == Some(socket_target.as_str()),
            "process closed or replaced the attributed socket"
        );

        let identity = ApplicationIdentity {
            pid,
            process_start_time_ticks: start_before,
            executable,
            executable_file,
            command_line,
            uid: uid_before,
            cgroups,
        };
        identity.validate()?;
        Ok(identity)
    }
}

fn enumerate_process_ids(root: &Path, deadline: Instant) -> Result<Vec<u32>> {
    let mut process_ids = Vec::new();
    ensure_within_deadline(deadline)?;
    for entry in fs::read_dir(root).context("cannot enumerate procfs")? {
        ensure_within_deadline(deadline)?;
        let entry = entry.context("cannot read procfs directory entry")?;
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Ok(process_id) = name.parse::<u32>() else {
            continue;
        };
        process_ids.push(process_id);
        ensure!(
            process_ids.len() <= MAX_PROC_ENTRIES,
            "procfs process bound exceeded"
        );
    }
    process_ids.sort_unstable();
    Ok(process_ids)
}

fn enumerate_task_ids(
    process: &Path,
    task_root: &Path,
    process_id: u32,
    deadline: Instant,
    task_count: &mut usize,
) -> Result<Option<Vec<u32>>> {
    let entries = match fs::read_dir(task_root) {
        Ok(entries) => entries,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            if path_disappeared(process)? {
                return Ok(None);
            }
            bail!(
                "cannot prove socket ownership: task list for live process {process_id} is unavailable"
            );
        }
        Err(error) => {
            return Err(error)
                .with_context(|| format!("cannot enumerate task list for process {process_id}"));
        }
    };
    let mut task_ids = Vec::new();
    for entry in entries {
        ensure_within_deadline(deadline)?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect task entry for process {process_id}")
                });
            }
        };
        let Some(name) = entry.file_name().to_str().map(ToOwned::to_owned) else {
            continue;
        };
        let Ok(task_id) = name.parse::<u32>() else {
            continue;
        };
        *task_count = task_count
            .checked_add(1)
            .ok_or_else(|| anyhow!("procfs task count overflow"))?;
        ensure!(
            *task_count <= MAX_PROC_ENTRIES,
            "procfs task bound exceeded"
        );
        task_ids.push(task_id);
    }
    task_ids.sort_unstable();
    if task_ids.is_empty() {
        if path_disappeared(process)? {
            return Ok(None);
        }
        bail!("cannot prove socket ownership: live process {process_id} has no enumerable tasks");
    }
    Ok(Some(task_ids))
}

fn task_owns_socket(
    task: &Path,
    process_id: u32,
    task_id: u32,
    target: &str,
    expected_uid: u32,
    deadline: Instant,
    maximum_fds: usize,
) -> Result<bool> {
    let observed_fsuid = match read_process_fs_uid(task, deadline) {
        Ok(uid) => uid,
        Err(error) => {
            if path_disappeared(task)? {
                return Ok(false);
            }
            return Err(error)
                .with_context(|| format!("cannot inspect filesystem UID for task {task_id}"));
        }
    };
    if observed_fsuid != expected_uid {
        return Ok(false);
    }
    let descriptors = match fs::read_dir(task.join("fd")) {
        Ok(entries) => entries,
        Err(error) if matches!(error.kind(), ErrorKind::NotFound | ErrorKind::NotADirectory) => {
            if path_disappeared(task)? {
                return Ok(false);
            }
            bail!(
                "cannot prove socket ownership: descriptor table for live task {task_id} is unavailable"
            );
        }
        Err(error) => {
            if error.kind() == ErrorKind::PermissionDenied
                && task_id == process_id
                && task_is_stably_zombie(task, deadline)?
            {
                // A terminated thread-group leader can remain as a zombie
                // while workers continue. Linux has already run exit_files()
                // for a zombie, so its inaccessible fd directory cannot hide
                // a socket owner. Continue scanning the live worker tasks.
                return Ok(false);
            }
            return Err(error)
                .with_context(|| format!("cannot enumerate descriptor table for task {task_id}"));
        }
    };
    ensure_within_deadline(deadline)?;
    for (count, entry) in descriptors.enumerate() {
        ensure!(
            count < maximum_fds,
            "cannot prove unique socket ownership: per-task fd bound exceeded"
        );
        ensure_within_deadline(deadline)?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("cannot inspect descriptor entry for task {task_id}")
                });
            }
        };
        let link = match fs::read_link(entry.path()) {
            Ok(link) => link.to_str().map(ToOwned::to_owned),
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("cannot inspect descriptor link for task {task_id}"));
            }
        };
        ensure_within_deadline(deadline)?;
        if link.as_deref() == Some(target) {
            let owner_uid = read_process_fs_uid(task, deadline)
                .with_context(|| format!("cannot verify socket owner task {task_id}"))?;
            ensure!(
                owner_uid == observed_fsuid && owner_uid == expected_uid,
                "socket owner filesystem UID differs from the kernel socket UID"
            );
            return Ok(true);
        }
    }
    Ok(false)
}

fn equivalent_enforcement_identity(
    left: &ApplicationIdentity,
    right: &ApplicationIdentity,
) -> bool {
    left.executable == right.executable
        && left.executable_file == right.executable_file
        && left.command_line == right.command_line
        && left.uid == right.uid
        && left.cgroups == right.cgroups
}

fn path_disappeared(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(true),
        Err(error) => {
            Err(error).with_context(|| format!("cannot recheck procfs path {}", path.display()))
        }
    }
}

fn task_is_stably_zombie(task: &Path, deadline: Instant) -> Result<bool> {
    let before = read_task_state(task, deadline)?;
    ensure_within_deadline(deadline)?;
    let after = read_task_state(task, deadline)?;
    Ok(before == b'Z' && after == b'Z')
}

fn read_task_state(task: &Path, deadline: Instant) -> Result<u8> {
    let bytes = read_bounded(&task.join("stat"), MAX_STAT_BYTES, deadline)?;
    let text = std::str::from_utf8(&bytes).context("task stat is not UTF-8 ASCII")?;
    let close = text
        .rfind(')')
        .ok_or_else(|| anyhow!("task stat has no command terminator"))?;
    let state = text
        .get(close + 1..)
        .ok_or_else(|| anyhow!("task stat is truncated"))?
        .split_ascii_whitespace()
        .next()
        .ok_or_else(|| anyhow!("task stat has no state field"))?;
    ensure!(
        state.len() == 1 && state.is_ascii(),
        "task stat state is invalid"
    );
    state
        .as_bytes()
        .first()
        .copied()
        .ok_or_else(|| anyhow!("task stat state disappeared"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SocketCandidate {
    local_address: IpAddr,
    local_port: u16,
    remote_address: IpAddr,
    remote_port: u16,
    uid: u32,
    inode: u64,
}

impl SocketCandidate {
    fn matches(self, connection: &OutboundConnection) -> bool {
        let Some(source_port) = connection.source_port else {
            return false;
        };
        let local_matches = self.local_port == source_port
            && (self.local_address == connection.source_address
                || self.local_address.is_unspecified());
        let remote_matches = (self.remote_address == connection.destination_address
            && self.remote_port == connection.destination_port.unwrap_or_default())
            || (self.remote_address.is_unspecified() && self.remote_port == 0);
        local_matches && remote_matches && self.inode != 0
    }
}

fn parse_socket_line(line: &str) -> Result<Option<SocketCandidate>> {
    let fields: Vec<&str> = line.split_ascii_whitespace().collect();
    if fields.len() < 10 {
        return Ok(None);
    }
    let (local_address, local_port) = parse_proc_endpoint(fields[1])?;
    let (remote_address, remote_port) = parse_proc_endpoint(fields[2])?;
    let uid = fields[7].parse::<u32>().context("invalid socket uid")?;
    let inode = fields[9].parse::<u64>().context("invalid socket inode")?;
    Ok(Some(SocketCandidate {
        local_address,
        local_port,
        remote_address,
        remote_port,
        uid,
        inode,
    }))
}

fn parse_proc_endpoint(value: &str) -> Result<(IpAddr, u16)> {
    let (address, port) = value
        .rsplit_once(':')
        .ok_or_else(|| anyhow!("socket endpoint has no port separator"))?;
    let port = u16::from_str_radix(port, 16).context("invalid socket port")?;
    let address = match address.len() {
        8 => {
            let raw = u32::from_str_radix(address, 16).context("invalid IPv4 socket address")?;
            IpAddr::V4(Ipv4Addr::from(raw.to_le_bytes()))
        }
        32 => {
            let mut octets = [0_u8; 16];
            for (index, chunk) in address.as_bytes().as_chunks::<8>().0.iter().enumerate() {
                let text = std::str::from_utf8(chunk).context("invalid IPv6 socket address")?;
                let raw =
                    u32::from_str_radix(text, 16).context("invalid IPv6 socket address word")?;
                octets[index * 4..index * 4 + 4].copy_from_slice(&raw.to_le_bytes());
            }
            IpAddr::V6(Ipv6Addr::from(octets))
        }
        _ => bail!("socket address has an invalid width"),
    };
    Ok((address, port))
}

fn find_socket_fd(process: &Path, target: &str, deadline: Instant) -> Result<PathBuf> {
    ensure_within_deadline(deadline)?;
    let entries = fs::read_dir(process.join("fd")).context("cannot enumerate process fds")?;
    ensure_within_deadline(deadline)?;
    for (count, entry) in entries.enumerate() {
        ensure_within_deadline(deadline)?;
        ensure!(count < MAX_FDS_PER_TASK, "per-task fd bound exceeded");
        let entry = entry.context("cannot inspect process fd")?;
        let link = fs::read_link(entry.path())
            .ok()
            .and_then(|link| link.to_str().map(ToOwned::to_owned));
        ensure_within_deadline(deadline)?;
        if link.as_deref() == Some(target) {
            return Ok(entry.path());
        }
    }
    bail!("attributed socket fd is no longer owned by the process")
}

fn read_process_fs_uid(process: &Path, deadline: Instant) -> Result<u32> {
    let bytes = read_bounded(&process.join("status"), MAX_STATUS_BYTES, deadline)?;
    let text = std::str::from_utf8(&bytes).context("process status is not UTF-8 ASCII")?;
    let line = text
        .lines()
        .find(|line| line.starts_with("Uid:"))
        .ok_or_else(|| anyhow!("process status has no Uid field"))?;
    line.split_ascii_whitespace()
        .nth(4)
        .ok_or_else(|| anyhow!("process Uid field does not contain an fsuid"))?
        .parse::<u32>()
        .context("process fsuid is invalid")
}

fn read_start_time(process: &Path, deadline: Instant) -> Result<u64> {
    let bytes = read_bounded(&process.join("stat"), MAX_STAT_BYTES, deadline)?;
    let text = std::str::from_utf8(&bytes).context("process stat is not UTF-8 ASCII")?;
    let close = text
        .rfind(')')
        .ok_or_else(|| anyhow!("process stat has no command terminator"))?;
    text.get(close + 1..)
        .ok_or_else(|| anyhow!("process stat is truncated"))?
        .split_ascii_whitespace()
        .nth(19)
        .ok_or_else(|| anyhow!("process stat has no start-time field"))?
        .parse::<u64>()
        .context("process start-time field is invalid")
}

fn read_command_line(process: &Path, deadline: Instant) -> Result<Vec<CommandArgument>> {
    let bytes = read_bounded(&process.join("cmdline"), MAX_COMMAND_LINE_BYTES, deadline)?;
    ensure!(!bytes.is_empty(), "process command line is empty");
    let mut raw_arguments: Vec<&[u8]> = bytes.split(|byte| *byte == 0).collect();
    if raw_arguments
        .last()
        .is_some_and(|argument| argument.is_empty())
    {
        raw_arguments.pop();
    }
    ensure!(
        !raw_arguments.is_empty() && raw_arguments.len() <= MAX_COMMAND_ARGUMENTS,
        "process command-line argument bound exceeded"
    );
    raw_arguments
        .into_iter()
        .map(|argument| {
            let argument = std::str::from_utf8(argument)
                .context("process command-line argument is not UTF-8")?;
            CommandArgument::new(argument.to_owned()).map_err(Into::into)
        })
        .collect()
}

fn read_cgroups(process: &Path, deadline: Instant) -> Result<Vec<CgroupPath>> {
    let bytes = read_bounded(&process.join("cgroup"), MAX_CGROUP_BYTES, deadline)?;
    let text = std::str::from_utf8(&bytes).context("process cgroup data is not UTF-8 ASCII")?;
    let mut unified = None;
    let mut memberships = 0_usize;
    for line in text.lines() {
        ensure_within_deadline(deadline)?;
        let mut fields = line.splitn(3, ':');
        let hierarchy = fields
            .next()
            .ok_or_else(|| anyhow!("process cgroup entry has no hierarchy"))?;
        let controllers = fields
            .next()
            .ok_or_else(|| anyhow!("process cgroup entry has no controller list"))?;
        let path = fields
            .next()
            .ok_or_else(|| anyhow!("process cgroup entry has no path"))?;
        let validated_path = CgroupPath::new(path.to_owned())?;
        memberships = memberships
            .checked_add(1)
            .ok_or_else(|| anyhow!("process cgroup membership count overflow"))?;
        if hierarchy == "0" && controllers.is_empty() {
            ensure!(
                unified.is_none(),
                "process has multiple unified cgroup v2 memberships"
            );
            unified = Some(validated_path);
        } else {
            let hierarchy = hierarchy
                .parse::<u32>()
                .context("process cgroup v1 hierarchy is invalid")?;
            ensure!(
                hierarchy != 0 && !controllers.is_empty(),
                "process cgroup membership mixes invalid hierarchy metadata"
            );
            ensure!(
                controllers.split(',').all(|controller| {
                    !controller.is_empty()
                        && controller.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'=')
                        })
                }),
                "process cgroup v1 controller list is invalid"
            );
        }
    }
    ensure_within_deadline(deadline)?;
    ensure!(memberships != 0, "process has no cgroup membership");
    // A cgroup selector is deliberately defined only against the unambiguous
    // unified-v2 path.  On a v1-only host retain no cgroup identity: selectors
    // which request one then fail to match, while executable/file/UID/argv
    // attribution remains available instead of denying every application.
    Ok(unified.into_iter().collect())
}

fn read_bounded(path: &Path, maximum: usize, deadline: Instant) -> Result<Vec<u8>> {
    ensure_within_deadline(deadline)?;
    let mut file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    ensure_within_deadline(deadline)?;
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 8 * 1024];
    loop {
        ensure_within_deadline(deadline)?;
        let count = file
            .read(&mut chunk)
            .with_context(|| format!("cannot read {}", path.display()))?;
        ensure_within_deadline(deadline)?;
        if count == 0 {
            break;
        }
        ensure!(
            bytes.len().saturating_add(count) <= maximum,
            "bounded procfs file is oversized"
        );
        bytes.extend_from_slice(&chunk[..count]);
    }
    Ok(bytes)
}

fn ensure_within_deadline(deadline: Instant) -> Result<()> {
    ensure!(Instant::now() <= deadline, "bounded procfs scan timed out");
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::error::Error;
    use std::os::unix::fs::symlink;

    use openshield_core::{
        ApplicationSelector, Direction, Mode, PortRange, RuleName, RuleOrigin, RuleSpec, State,
    };

    use super::*;

    fn create_task_fixture(
        root: &Path,
        process_id: u32,
        task_id: u32,
        uid: u32,
    ) -> Result<PathBuf, Box<dyn Error>> {
        let task = root
            .join(process_id.to_string())
            .join("task")
            .join(task_id.to_string());
        fs::create_dir_all(task.join("fd"))?;
        fs::write(
            task.join("status"),
            format!("Name:\ttest\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"),
        )?;
        Ok(task)
    }

    #[test]
    fn parses_proc_ipv4_and_ipv6_endpoints() -> Result<(), Box<dyn Error>> {
        assert_eq!(
            parse_proc_endpoint("0100007F:01BB")?,
            ("127.0.0.1".parse()?, 443)
        );
        assert_eq!(
            parse_proc_endpoint("B80D0120000000000000000001000000:0035")?,
            ("2001:db8::1".parse()?, 53)
        );
        Ok(())
    }

    #[test]
    fn application_rule_requires_every_network_and_process_selector() -> Result<(), Box<dyn Error>>
    {
        let interface = InterfaceName::new("eth0")?;
        let identity = ApplicationIdentity {
            pid: 10,
            process_start_time_ticks: 11,
            executable: ApplicationPath::new("/usr/bin/curl")?,
            executable_file: ExecutableFileId {
                device: 8,
                inode: 9,
                size: 10,
                ctime_seconds: 11,
                ctime_nanoseconds: 12,
            },
            command_line: vec![CommandArgument::new("curl")?],
            uid: 1_000,
            cgroups: vec![],
        };
        let mut spec = RuleSpec::new(
            RuleName::new("curl https")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.7/32".parse()?),
            Some(PortRange::single(443)?),
            Some(interface.clone()),
            RuleOrigin::Manual,
            true,
        )?;
        spec.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/usr/bin/curl")?),
            Some(identity.executable_file),
            None,
            Some(1_000),
            None,
        )?);
        spec.validate()?;
        let mut state = State::new();
        state.set_mode(Mode::Enforcing)?;
        state.create_rule(spec)?;
        let connection = OutboundConnection {
            source_address: "192.0.2.1".parse()?,
            source_port: Some(50_000),
            destination_address: "203.0.113.7".parse()?,
            destination_port: Some(443),
            protocol: TransportProtocol::Tcp,
            output_interface: interface,
            socket_uid: 1_000,
        };
        assert!(matching_application_rule(&state.snapshot(), &connection, &identity).is_some());

        let indexed = ApplicationDecisionPolicy::new(state.snapshot());
        assert_eq!(indexed.candidate_count(identity.executable_file), 1);
        assert!(indexed.matching_rule(&connection, &identity).is_some());

        let mut unrelated_binary = identity.clone();
        unrelated_binary.executable_file.inode += 1;
        assert_eq!(indexed.candidate_count(unrelated_binary.executable_file), 0);
        assert!(
            indexed
                .matching_rule(&connection, &unrelated_binary)
                .is_none()
        );

        let mut wrong_destination = connection;
        wrong_destination.destination_address = "203.0.113.8".parse()?;
        assert!(
            matching_application_rule(&state.snapshot(), &wrong_destination, &identity).is_none()
        );
        Ok(())
    }

    #[test]
    fn privileged_manual_rule_pins_the_opened_executable() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("application");
        fs::write(&executable, b"test executable")?;
        let executable_text = executable
            .to_str()
            .ok_or("temporary path is not UTF-8")?
            .to_owned();
        let mut specification = RuleSpec::new(
            RuleName::new("pinned application")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(executable_text)?),
            None,
            None,
            None,
            None,
        )?);

        pin_rule_application(&mut specification)?;

        let metadata = fs::metadata(fs::canonicalize(&executable)?)?;
        let selector = specification.application.ok_or("selector disappeared")?;
        assert_eq!(
            selector.executable_file,
            Some(ExecutableFileId {
                device: metadata.dev(),
                inode: metadata.ino(),
                size: metadata.size(),
                ctime_seconds: metadata.ctime(),
                ctime_nanoseconds: metadata.ctime_nsec(),
            })
        );
        Ok(())
    }

    #[test]
    fn privileged_manual_rule_rejects_stale_in_place_version() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("application");
        fs::write(&executable, b"old")?;
        let old_file = executable_file_id(&fs::metadata(&executable)?)?;
        fs::write(&executable, b"new executable contents")?;
        let new_file = executable_file_id(&fs::metadata(&executable)?)?;
        assert_eq!(old_file.device, new_file.device);
        assert_eq!(old_file.inode, new_file.inode);
        assert_ne!(old_file.size, new_file.size);

        let mut specification = RuleSpec::new(
            RuleName::new("stale application")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(
                executable.to_str().ok_or("temporary path is not UTF-8")?,
            )?),
            Some(old_file),
            None,
            None,
            None,
        )?);

        let Err(error) = pin_rule_application(&mut specification) else {
            return Err("stale pin was accepted".into());
        };
        assert!(error.to_string().contains("version does not match"));
        Ok(())
    }

    #[test]
    fn manual_pin_canonicalizes_a_stable_symlink() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("application");
        let link = directory.path().join("application-link");
        fs::write(&executable, b"test executable")?;
        symlink(&executable, &link)?;
        let mut specification = RuleSpec::new(
            RuleName::new("symlinked application")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new(
                link.to_str().ok_or("temporary path is not UTF-8")?,
            )?),
            None,
            None,
            None,
            None,
        )?);

        pin_rule_application(&mut specification)?;

        let selector = specification.application.ok_or("selector disappeared")?;
        assert_eq!(
            selector.executable.as_ref().map(ApplicationPath::as_str),
            fs::canonicalize(&executable)?.to_str()
        );
        Ok(())
    }

    #[test]
    fn nofollow_open_rejects_an_uncanonicalized_symlink() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let executable = directory.path().join("application");
        let link = directory.path().join("application-link");
        fs::write(&executable, b"test executable")?;
        symlink(&executable, &link)?;

        assert!(open_executable_version(&link).is_err());
        Ok(())
    }

    #[test]
    fn privileged_manual_rule_rejects_an_unresolvable_unpinned_path() -> Result<(), Box<dyn Error>>
    {
        let mut specification = RuleSpec::new(
            RuleName::new("missing application")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/definitely/missing/application")?),
            None,
            None,
            None,
            None,
        )?);
        assert!(pin_rule_application(&mut specification).is_err());
        Ok(())
    }

    #[test]
    fn privileged_manual_rule_rejects_an_unresolvable_supplied_version()
    -> Result<(), Box<dyn Error>> {
        let mut specification = RuleSpec::new(
            RuleName::new("missing supplied application")?,
            Direction::Outbound,
            TransportProtocol::Tcp,
            Some("203.0.113.1/32".parse()?),
            Some(PortRange::single(443)?),
            None,
            RuleOrigin::Manual,
            true,
        )?;
        specification.application = Some(ApplicationSelector::new(
            Some(ApplicationPath::new("/definitely/missing/application")?),
            Some(ExecutableFileId {
                device: 8,
                inode: 99,
                size: 12_345,
                ctime_seconds: 1_700_000_000,
                ctime_nanoseconds: 123_456_789,
            }),
            None,
            None,
            None,
        )?);

        assert!(pin_rule_application(&mut specification).is_err());
        Ok(())
    }

    #[test]
    fn start_time_parser_handles_spaces_and_parentheses_in_comm() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let pid = directory.path().join("123");
        fs::create_dir(&pid)?;
        let mut fields = vec!["S".to_owned(); 20];
        fields[19] = "987654".to_owned();
        fs::write(
            pid.join("stat"),
            format!("123 (odd ) name) {}\n", fields.join(" ")),
        )?;
        assert_eq!(
            read_start_time(&pid, Instant::now() + Duration::from_secs(1))?,
            987_654
        );
        Ok(())
    }

    #[test]
    fn zombie_state_parser_handles_spaces_and_parentheses_in_comm() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join("stat"), "200 (odd ) name) Z 1 2 3\n")?;
        let deadline = Instant::now() + Duration::from_secs(1);
        assert_eq!(read_task_state(directory.path(), deadline)?, b'Z');
        assert!(task_is_stably_zombie(directory.path(), deadline)?);
        Ok(())
    }

    #[test]
    fn process_identity_uses_the_socket_relevant_fsuid() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::write(
            directory.path().join("status"),
            "Name:\ttest\nUid:\t1000\t1001\t1002\t1003\n",
        )?;
        assert_eq!(
            read_process_fs_uid(directory.path(), Instant::now() + Duration::from_secs(1))?,
            1_003
        );
        Ok(())
    }

    #[test]
    fn cgroup_identity_uses_only_the_qualified_v2_unified_hierarchy() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        fs::write(
            directory.path().join("cgroup"),
            "5:cpu,cpuacct:/trusted\n0::/system.slice/application.scope\n",
        )?;

        assert_eq!(
            read_cgroups(directory.path(), Instant::now() + Duration::from_secs(1))?,
            vec![CgroupPath::new("/system.slice/application.scope")?]
        );
        Ok(())
    }

    #[test]
    fn cgroup_v1_keeps_non_cgroup_application_attribution_available() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        fs::write(
            directory.path().join("cgroup"),
            "5:cpu,cpuacct:/trusted\n4:memory:/trusted\n",
        )?;

        assert_eq!(
            read_cgroups(directory.path(), Instant::now() + Duration::from_secs(1))?,
            Vec::<CgroupPath>::new()
        );
        Ok(())
    }

    #[test]
    fn malformed_cgroup_v1_metadata_still_fails_closed() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::write(directory.path().join("cgroup"), "0:cpu:/trusted\n")?;

        assert!(read_cgroups(directory.path(), Instant::now() + Duration::from_secs(1)).is_err());
        Ok(())
    }

    #[test]
    fn incomplete_fd_scan_cannot_claim_unique_socket_ownership() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let known_owner = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        let bounded_task = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        symlink("socket:[77]", known_owner.join("fd/3"))?;
        symlink("socket:[1]", bounded_task.join("fd/3"))?;
        symlink("socket:[2]", bounded_task.join("fd/4"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let result = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            1,
        );

        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|error| error.to_string().contains("cannot prove unique"))
        );
        Ok(())
    }

    #[test]
    fn unrelated_uid_fd_bound_does_not_break_owner_search() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let known_owner = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        let unrelated_task = create_task_fixture(directory.path(), 200, 200, 2_000)?;
        symlink("socket:[77]", known_owner.join("fd/3"))?;
        symlink("socket:[1]", unrelated_task.join("fd/3"))?;
        symlink("socket:[2]", unrelated_task.join("fd/4"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let owners = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            1,
        )?;

        assert_eq!(owners.len(), 1);
        assert_eq!(owners[0].tid, 100);
        Ok(())
    }

    #[test]
    fn socket_transfer_to_another_fsuid_has_no_attributable_owner() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let recipient = create_task_fixture(directory.path(), 200, 200, 2_000)?;
        symlink("socket:[77]", recipient.join("fd/3"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let result = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        );

        assert!(result.is_err());
        assert!(result.err().is_some_and(|error| {
            error
                .to_string()
                .contains("no process owns the attributed socket inode")
        }));
        Ok(())
    }

    #[test]
    fn unshared_worker_fd_table_cannot_hide_a_second_process_owner() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        let allowed = create_task_fixture(directory.path(), 100, 100, 1_000)?;
        let _other_leader = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        let hidden_worker = create_task_fixture(directory.path(), 200, 201, 1_000)?;
        symlink("socket:[77]", allowed.join("fd/3"))?;
        symlink("socket:[77]", hidden_worker.join("fd/9"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let result = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        );

        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|error| error.to_string().contains("multiple processes"))
        );
        Ok(())
    }

    #[test]
    fn shared_fd_table_visible_to_sibling_tasks_is_one_process_owner() -> Result<(), Box<dyn Error>>
    {
        let directory = tempfile::tempdir()?;
        let leader = create_task_fixture(directory.path(), 200, 200, 1_000)?;
        let worker = create_task_fixture(directory.path(), 200, 201, 1_000)?;
        symlink("socket:[77]", leader.join("fd/3"))?;
        symlink("socket:[77]", worker.join("fd/3"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let owners = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        )?;

        assert_eq!(
            owners.iter().map(|owner| owner.tid).collect::<Vec<_>>(),
            vec![200, 201]
        );
        Ok(())
    }

    #[test]
    fn live_process_without_enumerable_tasks_fails_closed() -> Result<(), Box<dyn Error>> {
        let directory = tempfile::tempdir()?;
        fs::create_dir_all(directory.path().join("200/task"))?;

        let resolver = ProcfsResolver::at(directory.path());
        let result = resolver.resolve_unique_process_tasks(
            77,
            1_000,
            Instant::now() + Duration::from_secs(1),
            4,
        );

        assert!(result.is_err());
        assert!(
            result
                .err()
                .is_some_and(|error| error.to_string().contains("no enumerable tasks"))
        );
        Ok(())
    }

    #[test]
    fn fixture_root_is_not_implicitly_host_proc() -> Result<(), Box<dyn Error>> {
        let resolver = ProcfsResolver::at("/definitely/not/proc");
        let connection = OutboundConnection {
            source_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            source_port: Some(10),
            destination_address: IpAddr::V4(Ipv4Addr::LOCALHOST),
            destination_port: Some(20),
            protocol: TransportProtocol::Tcp,
            output_interface: InterfaceName::new("lo")?,
            socket_uid: 0,
        };
        assert!(resolver.resolve(&connection).is_err());
        Ok(())
    }
}
