#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("the B-002-S2 verifier supports only Linux and macOS");

use flate2::bufread::GzDecoder;
use rustix::fd::OwnedFd;
use rustix::fs::{
    flock, fstat, mkdirat, open, openat, statat, unlinkat, AtFlags, Dir, FileType, FlockOperation,
    Mode, OFlags,
};
use rustix::io::fcntl_dupfd_cloexec;
use rustix::io::Errno;
use rustix::process::{geteuid, umask};
use sha2::{Digest, Sha256};
use signal_hook::consts::signal::{SIGHUP, SIGINT, SIGTERM};
use signal_hook::{flag, low_level, SigId};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs::File;
#[cfg(test)]
use std::io::Write;
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::{atomic::AtomicUsize, atomic::Ordering, Arc};

const ACTIVE: usize = 0;
const SIGNALLED: usize = 1;
const COMMITTED: usize = 2;

const MAX_ARCHIVE_BYTES: u64 = 64 * 1024;
const MAX_EXPANDED_BYTES: usize = 256 * 1024;
const MAX_TAR_ENTRIES: usize = 64;
const MAX_TREE_ENTRIES: usize = 64;
const MAX_FILE_BYTES: usize = 32 * 1024;
const MAX_PATH_BYTES: usize = 240;
const WORKSPACE_PARENT: &str = "maverick-b002-s2-replay";
const WORKSPACE_CHILD: &str = "run";
const PRIVATE_ARCHIVE: &str = "input.crate";
const SYNTHETIC_GIT_COMMIT_OID: &str = "f946953e504032c3e8d74b172aba4c27a22dff7b";
const SYNTHETIC_GIT_COMMIT_BYTES: usize = 1100;
const SYNTHETIC_GIT_COMMIT_SHA256: [u8; 32] = [
    0x23, 0xf2, 0xc3, 0xe2, 0x74, 0x22, 0x11, 0x83, 0x8b, 0x71, 0x1b, 0x3e, 0x59, 0x54, 0xa0, 0x15,
    0x63, 0x29, 0x30, 0x7f, 0x59, 0xbd, 0x2f, 0x65, 0xa2, 0x22, 0xd9, 0x51, 0xc9, 0x4a, 0x57, 0xac,
];
const SYNTHETIC_GIT_TREE_OID: &str = "85775ab0088327b78c26db38cda26aad52c50596";
const SYNTHETIC_GIT_TREE_BYTES: usize = 917;
const SYNTHETIC_GIT_TREE_SHA256: [u8; 32] = [
    0x6d, 0x8f, 0x91, 0x58, 0xf2, 0x5d, 0x42, 0x24, 0xd1, 0x41, 0x7d, 0xf2, 0x35, 0x6b, 0x19, 0x2d,
    0xc5, 0xed, 0xf8, 0x88, 0xdd, 0x80, 0xb2, 0x71, 0xd9, 0xa4, 0xc9, 0x5f, 0x30, 0x80, 0x91, 0xbc,
];
const SYNTHETIC_GIT_BLOB_OID: &str = "010f002cf56497ce0a1b4ac124a2e2d86a97bc3d";
const SYNTHETIC_GIT_BLOB_BYTES: usize = 86;
const SYNTHETIC_GIT_BLOB_SHA256: [u8; 32] = [
    0x55, 0x9f, 0x48, 0x8c, 0x18, 0x1e, 0x0e, 0x9e, 0x77, 0xcf, 0x17, 0xc2, 0x9d, 0xe6, 0x63, 0x97,
    0x7f, 0x03, 0x6e, 0xc7, 0xff, 0x2e, 0x20, 0x60, 0x58, 0x57, 0x14, 0xbf, 0x53, 0xc5, 0x2d, 0x62,
];

#[cfg(target_os = "macos")]
const SYSTEM_TEMP: &str = "/private/tmp";
#[cfg(target_os = "linux")]
const SYSTEM_TEMP: &str = "/tmp";

const SYNTHETIC_PATCH: &[u8] =
    b"diff --git a/synthetic-0.0.0/src/message.txt b/synthetic-0.0.0/src/message.txt\n\
index 1111111..2222222 100644\n\
--- a/synthetic-0.0.0/src/message.txt\n\
+++ b/synthetic-0.0.0/src/message.txt\n\
@@ -1 +1 @@\n\
-before\n\
+after\n";
const SYNTHETIC_PATCH_ALLOWLIST: &[&str] = &["synthetic-0.0.0/src/message.txt"];

// S2 uses only deterministic synthetic bytes. S3 must replace these constants
// in a separately reviewed diff before any real archive is read.
const SYNTHETIC_ARCHIVE_BYTES: u64 = 158;
const SYNTHETIC_ARCHIVE_SHA256: [u8; 32] = [
    0x29, 0xfc, 0xc1, 0x33, 0x7a, 0x95, 0x12, 0x11, 0xe8, 0xbe, 0xc8, 0x4b, 0x46, 0x76, 0xab, 0x95,
    0xa7, 0xa2, 0xb7, 0x9d, 0xb9, 0x0d, 0xaa, 0x84, 0x91, 0xda, 0xdc, 0x94, 0xba, 0x2d, 0x7f, 0xc2,
];
const SYNTHETIC_INITIAL_TREE_SHA256: [u8; 32] = [
    0x0f, 0x92, 0xf8, 0x48, 0xf4, 0xf8, 0x5a, 0x4b, 0xab, 0x6a, 0x3f, 0xbd, 0x84, 0x8b, 0xea, 0x3d,
    0xb0, 0xa8, 0xc4, 0x83, 0x7b, 0xda, 0xe3, 0x50, 0x15, 0x44, 0x4b, 0x00, 0xf7, 0x85, 0x1d, 0xc5,
];
const SYNTHETIC_FINAL_TREE_SHA256: [u8; 32] = [
    0x50, 0xe8, 0xc4, 0x08, 0x41, 0xff, 0xea, 0x26, 0xba, 0x35, 0x44, 0x84, 0x78, 0x04, 0x5c, 0x54,
    0x7d, 0x63, 0x7b, 0x88, 0x6f, 0x05, 0x76, 0x2b, 0x4b, 0x13, 0xc0, 0x25, 0x9d, 0x54, 0xff, 0xf6,
];

#[derive(Clone, Copy)]
struct ArchiveSpec {
    exact_bytes: u64,
    maximum_bytes: u64,
    sha256: [u8; 32],
}

const SYNTHETIC_SPEC: ArchiveSpec = ArchiveSpec {
    exact_bytes: SYNTHETIC_ARCHIVE_BYTES,
    maximum_bytes: MAX_ARCHIVE_BYTES,
    sha256: SYNTHETIC_ARCHIVE_SHA256,
};

fn main() {
    run_signal_process(|| Ok(env::args_os().collect()), SYNTHETIC_SPEC, || true)
}

fn install_private_panic_hook() {
    std::panic::set_hook(Box::new(|_| {}));
}

struct SignalRegistrations {
    ids: [Option<SigId>; 3],
}

impl SignalRegistrations {
    fn install(state: Arc<AtomicUsize>) -> Self {
        let mut registrations = Self {
            ids: [None, None, None],
        };
        for (index, signal) in [SIGINT, SIGTERM, SIGHUP].into_iter().enumerate() {
            if test_registration_failure(index) {
                registrations.unregister_and_exit(1);
            }
            match flag::register_usize(signal, Arc::clone(&state), SIGNALLED) {
                Ok(id) => registrations.ids[index] = Some(id),
                Err(_) => registrations.unregister_and_exit(1),
            }
        }
        registrations
    }

    fn unregister_and_exit(mut self, expected_code: i32) -> ! {
        let mut removed_all = true;
        for id in self.ids.iter_mut().rev().filter_map(Option::take) {
            removed_all &= low_level::unregister(id);
        }
        std::process::exit(if removed_all { expected_code } else { 2 })
    }
}

#[cfg(not(test))]
fn test_registration_failure(_index: usize) -> bool {
    false
}

#[cfg(test)]
fn test_registration_failure(index: usize) -> bool {
    env::var("MAVERICK_B002_S2_REGISTER_FAILURE_AT")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        == Some(index)
}

fn run_signal_process(
    prepare_args: impl FnOnce() -> Result<Vec<OsString>, ()>,
    spec: ArchiveSpec,
    red_cleanup: impl FnOnce() -> bool,
) -> ! {
    install_private_panic_hook();
    let state = Arc::new(AtomicUsize::new(ACTIVE));
    let registrations = SignalRegistrations::install(Arc::clone(&state));
    let replay = catch_unwind(AssertUnwindSafe(|| -> Result<(), ()> {
        let args = prepare_args()?;
        let archive = parse_args(args)?;
        verify_replay(&archive, spec, state.as_ref())?;
        test_post_cleanup_signal_barrier(state.as_ref())?;
        state
            .compare_exchange(ACTIVE, COMMITTED, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| ())?;
        std::process::exit(0)
    }));
    let exit_checks = catch_unwind(AssertUnwindSafe(red_cleanup)).unwrap_or(false);
    let expected_red = matches!(replay, Ok(Err(()))) || replay.is_err();
    registrations.unregister_and_exit(if expected_red && exit_checks { 1 } else { 2 })
}

fn parse_args(args: impl IntoIterator<Item = OsString>) -> Result<PathBuf, ()> {
    let mut args = args.into_iter();
    let _program = args.next().ok_or(())?;
    let archive = PathBuf::from(args.next().ok_or(())?);
    if args.next().is_some() || !archive.is_absolute() {
        return Err(());
    }
    if archive.extension() != Some(OsStr::new("crate")) || has_ambiguous_component(&archive) {
        return Err(());
    }
    let repo = repository_root()?;
    if archive.starts_with(&repo) {
        return Err(());
    }
    Ok(archive)
}

fn has_ambiguous_component(path: &Path) -> bool {
    path.components()
        .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
}

fn repository_root() -> Result<PathBuf, ()> {
    let mut current = env::current_dir().map_err(|_| ())?;
    loop {
        if current.join(".git").exists() {
            return Ok(current);
        }
        if !current.pop() {
            return Err(());
        }
    }
}

#[cfg(test)]
fn verify(archive: &Path, spec: ArchiveSpec) -> Result<(), ()> {
    verify_replay(archive, spec, &AtomicUsize::new(ACTIVE))
}

fn verify_replay(archive: &Path, spec: ArchiveSpec, state: &AtomicUsize) -> Result<(), ()> {
    let input = open_and_hash_archive(archive, spec)?;
    check_active(state)?;
    let repo = repository_root()?;
    let repo_fd = open(&repo, directory_open_flags(), Mode::empty()).map_err(|_| ())?;
    let repo_identity = stat_identity(&fstat(&repo_fd).map_err(|_| ())?)?;
    read_fixed_git_chain(&repo)?;
    check_active(state)?;
    let mut mask = UmaskGuard::install();
    let replay = replay_worker(input, spec, repo_identity, state);
    mask.restore();
    replay
}

#[cfg(not(test))]
fn test_post_cleanup_signal_barrier(_state: &AtomicUsize) -> Result<(), ()> {
    Ok(())
}

#[cfg(test)]
fn test_post_cleanup_signal_barrier(state: &AtomicUsize) -> Result<(), ()> {
    if env::var_os("MAVERICK_B002_S2_POST_CLEANUP_SIGNAL_CHILD").is_none() {
        return Ok(());
    }
    println!("B-002-S2-POST-CLEANUP-READY");
    std::io::stdout().flush().map_err(|_| ())?;
    while state.load(Ordering::SeqCst) == ACTIVE {
        std::hint::spin_loop();
    }
    Ok(())
}

fn replay_worker(
    mut input: File,
    spec: ArchiveSpec,
    repo_identity: (u64, u64),
    state: &AtomicUsize,
) -> Result<(), ()> {
    check_active(state)?;
    let mut workspace = Workspace::create(repo_identity, state)?;
    let replay = (|| {
        let private = workspace.copy_archive(&mut input, spec, state)?;
        let expanded = decode_single_gzip_member_cancelled(
            std::io::Cursor::new(private),
            MAX_EXPANDED_BYTES,
            state,
        )?;
        let mut tree = parse_ustar_cancelled(&expanded, state)?;
        if tree_manifest_sha256(&tree) != SYNTHETIC_INITIAL_TREE_SHA256 {
            return Err(());
        }
        apply_unified_patch_cancelled(
            &mut tree,
            SYNTHETIC_PATCH,
            SYNTHETIC_PATCH_ALLOWLIST,
            state,
        )?;
        test_before_final_manifest_barrier(state)?;
        if tree_manifest_sha256(&tree) != SYNTHETIC_FINAL_TREE_SHA256 {
            return Err(());
        }
        check_active(state)?;
        test_after_final_manifest_barrier();
        check_active(state)
    })();
    let cleanup = workspace.cleanup();
    cleanup?;
    replay
}

fn check_active(state: &AtomicUsize) -> Result<(), ()> {
    if state.load(Ordering::SeqCst) == ACTIVE {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(not(test))]
fn test_before_final_manifest_barrier(_state: &AtomicUsize) -> Result<(), ()> {
    Ok(())
}

#[cfg(test)]
fn test_before_final_manifest_barrier(state: &AtomicUsize) -> Result<(), ()> {
    if env::var_os("MAVERICK_B002_S2_SIGNAL_CHILD").is_none() {
        return Ok(());
    }
    println!("B-002-S2-BEFORE-FINAL-MANIFEST-READY");
    std::io::stdout().flush().map_err(|_| ())?;
    while state.load(Ordering::SeqCst) == ACTIVE {
        std::hint::spin_loop();
    }
    check_active(state)
}

#[cfg(not(test))]
fn test_after_final_manifest_barrier() {}

#[cfg(test)]
fn test_after_final_manifest_barrier() {
    if env::var_os("MAVERICK_B002_S2_PANIC_CHILD").is_some() {
        panic!("private/example/path secret@example.invalid");
    }
}

fn read_fixed_git_chain(repo: &Path) -> Result<(), ()> {
    let commit = read_fixed_git_object(
        repo,
        "commit",
        SYNTHETIC_GIT_COMMIT_OID,
        SYNTHETIC_GIT_COMMIT_BYTES,
        SYNTHETIC_GIT_COMMIT_SHA256,
    )?;
    if !commit.starts_with(format!("tree {SYNTHETIC_GIT_TREE_OID}\n").as_bytes()) {
        return Err(());
    }
    let tree = read_fixed_git_object(
        repo,
        "tree",
        SYNTHETIC_GIT_TREE_OID,
        SYNTHETIC_GIT_TREE_BYTES,
        SYNTHETIC_GIT_TREE_SHA256,
    )?;
    let mut expected_tree_entry = b"100644 rust-toolchain.toml\0".to_vec();
    expected_tree_entry.extend_from_slice(&decode_oid_hex(SYNTHETIC_GIT_BLOB_OID)?);
    if tree
        .windows(expected_tree_entry.len())
        .filter(|window| *window == expected_tree_entry)
        .count()
        != 1
    {
        return Err(());
    }
    let _blob = read_fixed_git_object(
        repo,
        "blob",
        SYNTHETIC_GIT_BLOB_OID,
        SYNTHETIC_GIT_BLOB_BYTES,
        SYNTHETIC_GIT_BLOB_SHA256,
    )?;
    Ok(())
}

fn decode_oid_hex(oid: &str) -> Result<Vec<u8>, ()> {
    if oid.len() != 40 || !oid.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(());
    }
    oid.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let pair = std::str::from_utf8(pair).map_err(|_| ())?;
            u8::from_str_radix(pair, 16).map_err(|_| ())
        })
        .collect()
}

fn read_fixed_git_object(
    repo: &Path,
    kind: &str,
    oid: &str,
    exact_bytes: usize,
    sha256: [u8; 32],
) -> Result<Vec<u8>, ()> {
    let mut child = Command::new("/usr/bin/git")
        .arg("--no-pager")
        .arg("--no-replace-objects")
        .arg("--no-lazy-fetch")
        .arg("-c")
        .arg("core.pager=cat")
        .arg("-c")
        .arg("core.hooksPath=/dev/null")
        .arg("-c")
        .arg("core.fsmonitor=false")
        .arg("-c")
        .arg("core.attributesFile=/dev/null")
        .arg("-c")
        .arg("protocol.allow=never")
        .args(["cat-file", kind, oid])
        .current_dir(repo)
        .env_clear()
        .env("GIT_NO_REPLACE_OBJECTS", "1")
        .env("GIT_NO_LAZY_FETCH", "1")
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_ATTR_NOSYSTEM", "1")
        .env("GIT_EXEC_PATH", "/dev/null")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| ())?;
    let mut stdout = child.stdout.take().ok_or(())?;
    let mut bytes = Vec::with_capacity(exact_bytes.saturating_add(1));
    stdout
        .by_ref()
        .take(u64::try_from(exact_bytes.saturating_add(1)).map_err(|_| ())?)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > exact_bytes {
        let _ = child.kill();
        let _ = child.wait();
        return Err(());
    }
    let status = child.wait().map_err(|_| ())?;
    if !status.success()
        || bytes.len() != exact_bytes
        || <[u8; 32]>::from(Sha256::digest(&bytes)) != sha256
    {
        return Err(());
    }
    Ok(bytes)
}

struct UmaskGuard {
    previous: Mode,
    restored: bool,
}

impl UmaskGuard {
    fn install() -> Self {
        Self {
            previous: umask(Mode::RWXG | Mode::RWXO),
            restored: false,
        }
    }

    fn restore(&mut self) {
        if !self.restored {
            umask(self.previous);
            self.restored = true;
        }
    }
}

impl Drop for UmaskGuard {
    fn drop(&mut self) {
        self.restore();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LedgerKind {
    Directory,
    File,
}

#[derive(Debug)]
struct LedgerEntry {
    path: String,
    kind: LedgerKind,
    device: u64,
    inode: u64,
}

struct PendingEntry {
    parent_fd: OwnedFd,
    name: String,
    kind: LedgerKind,
    identity: Option<(u64, u64)>,
    active: bool,
}

impl PendingEntry {
    fn prepare(parent_fd: &OwnedFd, name: &str, kind: LedgerKind) -> Result<Self, ()> {
        Ok(Self {
            parent_fd: fcntl_dupfd_cloexec(parent_fd, 3).map_err(|_| ())?,
            name: name.to_owned(),
            kind,
            identity: None,
            active: true,
        })
    }

    fn bind_object(&mut self, object: &impl std::os::fd::AsFd) -> Result<(u64, u64), ()> {
        if self.identity.is_some() {
            return Err(());
        }
        let object_stat = fstat(object).map_err(|_| ())?;
        if !owned_entry(&object_stat, self.kind) {
            return Err(());
        }
        let identity = stat_identity(&object_stat)?;
        self.identity = Some(identity);
        let linked_stat = statat(
            &self.parent_fd,
            self.name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| ())?;
        if !owned_entry(&linked_stat, self.kind) || stat_identity(&linked_stat)? != identity {
            return Err(());
        }
        Ok(identity)
    }

    fn into_ledger(mut self, path: String) -> Result<LedgerEntry, ()> {
        let (device, inode) = self.identity.ok_or(())?;
        self.active = false;
        Ok(LedgerEntry {
            path,
            kind: self.kind,
            device,
            inode,
        })
    }

    fn disarm(mut self) {
        self.active = false;
    }

    fn rollback(&mut self) -> Result<(), ()> {
        if !self.active {
            return Ok(());
        }
        let identity = self.identity.ok_or(())?;
        let stat = statat(
            &self.parent_fd,
            self.name.as_str(),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(|_| ())?;
        if stat_identity(&stat)? != identity || !owned_entry(&stat, self.kind) {
            return Err(());
        }
        let flags = match self.kind {
            LedgerKind::Directory => AtFlags::REMOVEDIR,
            LedgerKind::File => AtFlags::empty(),
        };
        unlinkat(&self.parent_fd, self.name.as_str(), flags).map_err(|_| ())?;
        self.active = false;
        Ok(())
    }
}

impl Drop for PendingEntry {
    fn drop(&mut self) {
        let _ = self.rollback();
    }
}

struct Workspace {
    base_fd: OwnedFd,
    parent_fd: OwnedFd,
    child_fd: OwnedFd,
    base_device: u64,
    base_inode: u64,
    parent_device: u64,
    parent_inode: u64,
    child_device: u64,
    child_inode: u64,
    ledger: Vec<LedgerEntry>,
    cleaned: bool,
}

impl Workspace {
    fn create(repo_identity: (u64, u64), state: &AtomicUsize) -> Result<Self, ()> {
        check_active(state)?;
        let base_fd = open(
            SYSTEM_TEMP,
            OFlags::RDONLY
                | OFlags::DIRECTORY
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|_| ())?;
        let base = fstat(&base_fd).map_err(|_| ())?;
        let (base_device, base_inode) = stat_identity(&base)?;
        validate_workspace_base(&base_fd, &base, (base_device, base_inode), repo_identity)?;

        match mkdirat(&base_fd, WORKSPACE_PARENT, Mode::RWXU) {
            Ok(()) | Err(Errno::EXIST) => {}
            Err(_) => return Err(()),
        }
        let parent_fd = openat(
            &base_fd,
            WORKSPACE_PARENT,
            directory_open_flags(),
            Mode::empty(),
        )
        .map_err(|_| ())?;
        let parent = fstat(&parent_fd).map_err(|_| ())?;
        if !owned_private_directory(&parent) {
            return Err(());
        }
        let (parent_device, parent_inode) = stat_identity(&parent)?;
        let parent_link =
            statat(&base_fd, WORKSPACE_PARENT, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
        if stat_identity(&parent_link)? != (parent_device, parent_inode)
            || !owned_private_directory(&parent_link)
        {
            return Err(());
        }
        if !directory_is_empty(&parent_fd)? {
            return Err(());
        }
        flock(&parent_fd, FlockOperation::NonBlockingLockExclusive).map_err(|_| ())?;
        let locked_parent = fstat(&parent_fd).map_err(|_| ())?;
        if locked_parent.st_dev != parent.st_dev
            || locked_parent.st_ino != parent.st_ino
            || !owned_private_directory(&locked_parent)
            || !directory_is_empty(&parent_fd)?
        {
            return Err(());
        }
        let locked_link =
            statat(&base_fd, WORKSPACE_PARENT, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
        if stat_identity(&locked_link)? != (parent_device, parent_inode)
            || !owned_private_directory(&locked_link)
        {
            return Err(());
        }

        check_active(state)?;
        let mut pending_child =
            PendingEntry::prepare(&parent_fd, WORKSPACE_CHILD, LedgerKind::Directory)?;
        let reserved = reserve_descriptor_for_directory_bind()?;
        mkdirat(&parent_fd, WORKSPACE_CHILD, Mode::RWXU).map_err(|_| ())?;
        drop(reserved);
        let child_fd = openat(
            &parent_fd,
            WORKSPACE_CHILD,
            directory_open_flags(),
            Mode::empty(),
        )
        .map_err(|_| ())?;
        let linked_identity = pending_child.bind_object(&child_fd)?;
        let child = fstat(&child_fd).map_err(|_| ())?;
        let (child_device, child_inode) = stat_identity(&child)?;
        if !owned_private_directory(&child) || linked_identity != (child_device, child_inode) {
            return Err(());
        }
        check_active(state)?;
        pending_child.disarm();

        Ok(Self {
            base_fd,
            parent_fd,
            child_fd,
            base_device,
            base_inode,
            parent_device,
            parent_inode,
            child_device,
            child_inode,
            ledger: Vec::new(),
            cleaned: false,
        })
    }

    fn copy_archive(
        &mut self,
        input: &mut File,
        spec: ArchiveSpec,
        state: &AtomicUsize,
    ) -> Result<Vec<u8>, ()> {
        input.seek(SeekFrom::Start(0)).map_err(|_| ())?;
        self.ledger.try_reserve(1).map_err(|_| ())?;
        let mut pending = PendingEntry::prepare(&self.child_fd, PRIVATE_ARCHIVE, LedgerKind::File)?;
        let fd = openat(
            &self.child_fd,
            PRIVATE_ARCHIVE,
            OFlags::RDWR
                | OFlags::CREATE
                | OFlags::EXCL
                | OFlags::NOFOLLOW
                | OFlags::NONBLOCK
                | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(|_| ())?;
        let linked_identity = pending.bind_object(&fd)?;
        let stat = fstat(&fd).map_err(|_| ())?;
        let (device, inode) = stat_identity(&stat)?;
        if linked_identity != (device, inode) || !owned_entry(&stat, LedgerKind::File) {
            return Err(());
        }
        self.ledger
            .push(pending.into_ledger(PRIVATE_ARCHIVE.to_owned())?);

        let mut private = File::from(fd);
        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut chunk = [0_u8; 8192];
        loop {
            check_active(state)?;
            let read = input.read(&mut chunk).map_err(|_| ())?;
            if read == 0 {
                break;
            }
            total = total.checked_add(read as u64).ok_or(())?;
            if total > spec.exact_bytes {
                return Err(());
            }
            use std::io::Write;
            private.write_all(&chunk[..read]).map_err(|_| ())?;
            hasher.update(&chunk[..read]);
        }
        if total != spec.exact_bytes || <[u8; 32]>::from(hasher.finalize()) != spec.sha256 {
            return Err(());
        }
        test_private_rehash_barrier()?;
        private.seek(SeekFrom::Start(0)).map_err(|_| ())?;
        let read_limit = spec.exact_bytes.checked_add(1).ok_or(())?;
        let mut authenticated = Vec::with_capacity(usize::try_from(read_limit).map_err(|_| ())?);
        std::io::Read::by_ref(&mut private)
            .take(read_limit)
            .read_to_end(&mut authenticated)
            .map_err(|_| ())?;
        if authenticated.len() as u64 != spec.exact_bytes
            || <[u8; 32]>::from(Sha256::digest(&authenticated)) != spec.sha256
        {
            return Err(());
        }
        let final_stat = fstat(&private).map_err(|_| ())?;
        let final_link =
            statat(&self.child_fd, PRIVATE_ARCHIVE, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
        if stat_identity(&final_stat)? != (device, inode)
            || stat_identity(&final_link)? != (device, inode)
            || !owned_entry(&final_stat, LedgerKind::File)
            || !owned_entry(&final_link, LedgerKind::File)
            || u64::try_from(final_stat.st_size).map_err(|_| ())? != spec.exact_bytes
        {
            return Err(());
        }
        Ok(authenticated)
    }

    fn cleanup(&mut self) -> Result<(), ()> {
        if self.cleaned {
            return Ok(());
        }
        self.validate_anchors()?;
        let parent = fstat(&self.parent_fd).map_err(|_| ())?;
        let child = fstat(&self.child_fd).map_err(|_| ())?;
        if stat_identity(&parent)? != (self.parent_device, self.parent_inode)
            || !owned_private_directory(&parent)
            || stat_identity(&child)? != (self.child_device, self.child_inode)
            || !owned_private_directory(&child)
        {
            return Err(());
        }

        if self.ledger.len() > 1 {
            return Err(());
        }
        if let Some(entry) = self.ledger.last() {
            if entry.path != PRIVATE_ARCHIVE || entry.kind != LedgerKind::File {
                return Err(());
            }
            let stat = statat(&self.child_fd, PRIVATE_ARCHIVE, AtFlags::SYMLINK_NOFOLLOW)
                .map_err(|_| ())?;
            if stat_identity(&stat)? != (entry.device, entry.inode)
                || !owned_entry(&stat, LedgerKind::File)
            {
                return Err(());
            }
            unlinkat(&self.child_fd, PRIVATE_ARCHIVE, AtFlags::empty()).map_err(|_| ())?;
            self.ledger.pop();
        }
        if !directory_is_empty(&self.child_fd)? {
            return Err(());
        }
        let linked =
            statat(&self.parent_fd, WORKSPACE_CHILD, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
        if stat_identity(&linked)? != (self.child_device, self.child_inode)
            || !owned_private_directory(&linked)
        {
            return Err(());
        }
        unlinkat(&self.parent_fd, WORKSPACE_CHILD, AtFlags::REMOVEDIR).map_err(|_| ())?;
        self.validate_anchors()?;
        if !directory_is_empty(&self.parent_fd)? {
            return Err(());
        }
        self.cleaned = true;
        Ok(())
    }

    fn validate_anchors(&self) -> Result<(), ()> {
        let base = fstat(&self.base_fd).map_err(|_| ())?;
        let parent = fstat(&self.parent_fd).map_err(|_| ())?;
        let linked =
            statat(&self.base_fd, WORKSPACE_PARENT, AtFlags::SYMLINK_NOFOLLOW).map_err(|_| ())?;
        if stat_identity(&base)? != (self.base_device, self.base_inode)
            || !FileType::from_raw_mode(base.st_mode).is_dir()
            || base.st_uid != 0
            || base.st_mode & 0o7777 != 0o1777
            || stat_identity(&parent)? != (self.parent_device, self.parent_inode)
            || !owned_private_directory(&parent)
            || stat_identity(&linked)? != (self.parent_device, self.parent_inode)
            || !owned_private_directory(&linked)
        {
            return Err(());
        }
        Ok(())
    }
}

#[cfg(not(test))]
fn test_private_rehash_barrier() -> Result<(), ()> {
    Ok(())
}

#[cfg(test)]
static PRIVATE_REHASH_TEST_BARRIER_ENABLED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static PRIVATE_REHASH_TEST_BARRIER_READY: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static PRIVATE_REHASH_TEST_BARRIER_RELEASE: AtomicBool = AtomicBool::new(false);

#[cfg(test)]
fn test_private_rehash_barrier() -> Result<(), ()> {
    if !PRIVATE_REHASH_TEST_BARRIER_ENABLED.load(Ordering::Acquire) {
        return Ok(());
    }
    PRIVATE_REHASH_TEST_BARRIER_READY.store(true, Ordering::Release);
    while !PRIVATE_REHASH_TEST_BARRIER_RELEASE.load(Ordering::Acquire) {
        std::hint::spin_loop();
    }
    Ok(())
}

impl Drop for Workspace {
    fn drop(&mut self) {
        if !self.cleaned {
            let _ = self.cleanup();
        }
    }
}

fn directory_open_flags() -> OFlags {
    OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC
}

fn validate_workspace_base(
    base_fd: &OwnedFd,
    base: &rustix::fs::Stat,
    base_identity: (u64, u64),
    repo_identity: (u64, u64),
) -> Result<(), ()> {
    if !FileType::from_raw_mode(base.st_mode).is_dir()
        || base.st_uid != 0
        || base.st_mode & 0o7777 != 0o1777
        || stat_identity(base)? != base_identity
    {
        return Err(());
    }

    let mut seen = BTreeSet::new();
    let mut current = fcntl_dupfd_cloexec(base_fd, 3).map_err(|_| ())?;
    loop {
        let current_identity = stat_identity(&fstat(&current).map_err(|_| ())?)?;
        if current_identity == repo_identity || !seen.insert(current_identity) {
            return Err(());
        }
        let parent =
            openat(&current, "..", directory_open_flags(), Mode::empty()).map_err(|_| ())?;
        let parent_identity = stat_identity(&fstat(&parent).map_err(|_| ())?)?;
        if parent_identity == current_identity {
            return Ok(());
        }
        current = parent;
    }
}

fn reserve_descriptor_for_directory_bind() -> Result<OwnedFd, ()> {
    #[cfg(test)]
    if RESERVE_DESCRIPTOR_TEST_FAILURE.load(Ordering::Acquire) {
        return Err(());
    }
    open(
        "/dev/null",
        OFlags::RDONLY | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| ())
}

#[cfg(test)]
static RESERVE_DESCRIPTOR_TEST_FAILURE: AtomicBool = AtomicBool::new(false);

fn owned_private_directory(stat: &rustix::fs::Stat) -> bool {
    FileType::from_raw_mode(stat.st_mode).is_dir()
        && stat.st_uid == geteuid().as_raw()
        && stat.st_mode & 0o7777 == 0o700
}

fn owned_entry(stat: &rustix::fs::Stat, kind: LedgerKind) -> bool {
    stat.st_uid == geteuid().as_raw()
        && match kind {
            LedgerKind::Directory => {
                FileType::from_raw_mode(stat.st_mode).is_dir() && stat.st_mode & 0o7777 == 0o700
            }
            LedgerKind::File => {
                FileType::from_raw_mode(stat.st_mode).is_file() && stat.st_mode & 0o7777 == 0o600
            }
        }
}

fn stat_identity(stat: &rustix::fs::Stat) -> Result<(u64, u64), ()> {
    let inode = stat.st_ino;
    Ok((stat_device(stat)?, inode))
}

#[cfg(target_os = "linux")]
fn stat_device(stat: &rustix::fs::Stat) -> Result<u64, ()> {
    Ok(stat.st_dev)
}

#[cfg(target_os = "macos")]
fn stat_device(stat: &rustix::fs::Stat) -> Result<u64, ()> {
    u64::try_from(stat.st_dev).map_err(|_| ())
}

fn directory_is_empty(fd: &OwnedFd) -> Result<bool, ()> {
    let mut directory = Dir::read_from(fd).map_err(|_| ())?;
    for entry in &mut directory {
        let entry = entry.map_err(|_| ())?;
        let name = entry.file_name().to_bytes();
        if name != b"." && name != b".." {
            return Ok(false);
        }
    }
    Ok(true)
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum TreeEntry {
    Directory,
    File(Vec<u8>),
}

type Tree = BTreeMap<String, TreeEntry>;

#[cfg(test)]
fn parse_ustar(tar: &[u8]) -> Result<Tree, ()> {
    parse_ustar_cancelled(tar, &AtomicUsize::new(ACTIVE))
}

fn parse_ustar_cancelled(tar: &[u8], state: &AtomicUsize) -> Result<Tree, ()> {
    if tar.len() < 1024 || !tar.len().is_multiple_of(512) {
        return Err(());
    }
    let mut offset = 0_usize;
    let mut zero_blocks = 0_usize;
    let mut declared = BTreeSet::new();
    let mut portable_paths = BTreeMap::new();
    let mut tree = Tree::new();
    let mut file_bytes = 0_usize;

    while offset < tar.len() {
        check_active(state)?;
        let header = &tar[offset..offset + 512];
        if header.iter().all(|byte| *byte == 0) {
            zero_blocks += 1;
            offset += 512;
            if zero_blocks == 2 {
                if tar[offset..].iter().any(|byte| *byte != 0) {
                    return Err(());
                }
                return if declared.is_empty() {
                    Err(())
                } else {
                    Ok(tree)
                };
            }
            continue;
        }
        if zero_blocks != 0 || declared.len() >= MAX_TAR_ENTRIES {
            return Err(());
        }

        verify_tar_checksum(header)?;
        let path = tar_path(header)?;
        if !declared.insert(path.clone()) {
            return Err(());
        }
        register_portable_path(&mut portable_paths, &path)?;
        for field in [
            &header[100..108],
            &header[108..116],
            &header[116..124],
            &header[136..148],
        ] {
            parse_octal(field)?;
        }
        if header[157..257].iter().any(|byte| *byte != 0)
            || header[329..345].iter().any(|byte| *byte != 0)
            || header[500..512].iter().any(|byte| *byte != 0)
        {
            return Err(());
        }
        let size = usize::try_from(parse_octal(&header[124..136])?).map_err(|_| ())?;
        let kind = header[156];
        offset = offset.checked_add(512).ok_or(())?;
        let padded = size.checked_add(511).ok_or(())? / 512 * 512;
        let end = offset.checked_add(padded).ok_or(())?;
        if end > tar.len() || offset.checked_add(size).ok_or(())? > tar.len() {
            return Err(());
        }

        insert_inferred_directories(&mut tree, &path)?;
        match kind {
            0 | b'0' => {
                if size > MAX_FILE_BYTES {
                    return Err(());
                }
                file_bytes = file_bytes.checked_add(size).ok_or(())?;
                if file_bytes > MAX_EXPANDED_BYTES {
                    return Err(());
                }
                if tree
                    .insert(path, TreeEntry::File(tar[offset..offset + size].to_vec()))
                    .is_some()
                {
                    return Err(());
                }
                if tree.len() > MAX_TREE_ENTRIES {
                    return Err(());
                }
            }
            b'5' if size == 0 => {
                if tree.contains_key(&path) {
                    return Err(());
                }
                tree.insert(path, TreeEntry::Directory);
                if tree.len() > MAX_TREE_ENTRIES {
                    return Err(());
                }
            }
            _ => return Err(()),
        }
        if tar[offset + size..end].iter().any(|byte| *byte != 0) {
            return Err(());
        }
        offset = end;
    }
    Err(())
}

fn verify_tar_checksum(header: &[u8]) -> Result<(), ()> {
    let expected = parse_octal(&header[148..156])?;
    let actual = header
        .iter()
        .enumerate()
        .map(|(index, byte)| {
            if (148..156).contains(&index) {
                u64::from(b' ')
            } else {
                u64::from(*byte)
            }
        })
        .sum::<u64>();
    if actual == expected {
        Ok(())
    } else {
        Err(())
    }
}

fn parse_octal(field: &[u8]) -> Result<u64, ()> {
    if field.is_empty() || field[0] & 0x80 != 0 {
        return Err(());
    }
    let mut value = 0_u64;
    let mut saw_digit = false;
    let mut ended = false;
    for byte in field {
        match *byte {
            b'0'..=b'7' if !ended => {
                saw_digit = true;
                value = value
                    .checked_mul(8)
                    .and_then(|current| current.checked_add(u64::from(*byte - b'0')))
                    .ok_or(())?;
            }
            0 | b' ' => {
                if saw_digit {
                    ended = true;
                }
            }
            _ => return Err(()),
        }
    }
    if saw_digit {
        Ok(value)
    } else {
        Err(())
    }
}

fn tar_path(header: &[u8]) -> Result<String, ()> {
    let (name, prefix) = match (&header[257..263], &header[263..265]) {
        (b"ustar\0", b"00") => (tar_text(&header[..100])?, tar_text(&header[345..500])?),
        (b"ustar ", b" \0") => {
            if header[345..].iter().any(|byte| *byte != 0) {
                return Err(());
            }
            (tar_text(&header[..100])?, Vec::new())
        }
        _ => return Err(()),
    };
    if name.is_empty() {
        return Err(());
    }
    let mut bytes = prefix;
    if !bytes.is_empty() {
        bytes.push(b'/');
    }
    bytes.extend_from_slice(&name);
    validate_portable_path(&bytes)
}

fn tar_text(field: &[u8]) -> Result<Vec<u8>, ()> {
    let end = field
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(field.len());
    if field[end..].iter().any(|byte| *byte != 0) {
        return Err(());
    }
    Ok(field[..end].to_vec())
}

fn validate_portable_path(bytes: &[u8]) -> Result<String, ()> {
    if bytes.is_empty()
        || bytes.len() > MAX_PATH_BYTES
        || bytes[0] == b'/'
        || bytes.contains(&b'\\')
        || !bytes.iter().all(|byte| byte.is_ascii_graphic())
    {
        return Err(());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ())?;
    if text
        .split('/')
        .any(|part| part.is_empty() || part == "." || part == "..")
    {
        return Err(());
    }
    Ok(text.to_owned())
}

fn insert_inferred_directories(tree: &mut Tree, path: &str) -> Result<(), ()> {
    let parts = path.split('/').collect::<Vec<_>>();
    let mut parent = String::new();
    for part in parts.iter().take(parts.len().saturating_sub(1)) {
        if !parent.is_empty() {
            parent.push('/');
        }
        parent.push_str(part);
        match tree.get(&parent) {
            Some(TreeEntry::File(_)) => return Err(()),
            Some(TreeEntry::Directory) => {}
            None => {
                if tree.len() >= MAX_TREE_ENTRIES {
                    return Err(());
                }
                tree.insert(parent.clone(), TreeEntry::Directory);
            }
        }
    }
    if tree
        .keys()
        .any(|existing| existing.starts_with(&format!("{path}/")))
    {
        return Err(());
    }
    Ok(())
}

fn register_portable_path(paths: &mut BTreeMap<String, String>, path: &str) -> Result<(), ()> {
    let mut prefix = String::new();
    for component in path.split('/') {
        if !prefix.is_empty() {
            prefix.push('/');
        }
        prefix.push_str(component);
        let key = prefix.to_ascii_lowercase();
        match paths.get(&key) {
            Some(existing) if existing != &prefix => return Err(()),
            Some(_) => {}
            None => {
                paths.insert(key, prefix.clone());
            }
        }
    }
    Ok(())
}

fn tree_manifest_sha256(tree: &Tree) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for (path, entry) in tree {
        match entry {
            TreeEntry::Directory => {
                hasher.update(b"D\0");
                hasher.update(path.as_bytes());
                hasher.update(b"\n");
            }
            TreeEntry::File(bytes) => {
                hasher.update(b"F\0");
                hasher.update(path.as_bytes());
                hasher.update(b"\0");
                hasher.update(bytes.len().to_string().as_bytes());
                hasher.update(b"\0");
                hasher.update(Sha256::digest(bytes));
                hasher.update(b"\n");
            }
        }
    }
    hasher.finalize().into()
}

#[cfg(test)]
fn apply_unified_patch(tree: &mut Tree, patch: &[u8], allowlist: &[&str]) -> Result<(), ()> {
    apply_unified_patch_cancelled(tree, patch, allowlist, &AtomicUsize::new(ACTIVE))
}

fn apply_unified_patch_cancelled(
    tree: &mut Tree,
    patch: &[u8],
    allowlist: &[&str],
    state: &AtomicUsize,
) -> Result<(), ()> {
    if patch.is_empty() || !patch.ends_with(b"\n") {
        return Err(());
    }
    let text = std::str::from_utf8(patch).map_err(|_| ())?;
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    let allowed = allowlist.iter().copied().collect::<BTreeSet<_>>();
    let mut touched = BTreeSet::new();
    let mut index = 0_usize;

    while index < lines.len() {
        check_active(state)?;
        let diff = lines.get(index).ok_or(())?.strip_suffix('\n').ok_or(())?;
        let rest = diff.strip_prefix("diff --git a/").ok_or(())?;
        let (left, right) = rest.split_once(" b/").ok_or(())?;
        if left != right || !allowed.contains(left) || !touched.insert(left.to_owned()) {
            return Err(());
        }
        index += 1;
        let index_line = lines.get(index).ok_or(())?.strip_suffix('\n').ok_or(())?;
        if !valid_index_line(index_line) {
            return Err(());
        }
        index += 1;
        if lines.get(index).copied() != Some(format!("--- a/{left}\n").as_str()) {
            return Err(());
        }
        index += 1;
        if lines.get(index).copied() != Some(format!("+++ b/{left}\n").as_str()) {
            return Err(());
        }
        index += 1;

        let original = match tree.get(left) {
            Some(TreeEntry::File(bytes)) => bytes.clone(),
            _ => return Err(()),
        };
        let source = split_lines(&original);
        let mut output = Vec::new();
        let mut source_cursor = 0_usize;
        let mut saw_hunk = false;
        while index < lines.len() && lines[index].starts_with("@@ ") {
            check_active(state)?;
            saw_hunk = true;
            let (old_start, old_count, new_start, new_count) = parse_hunk_header(lines[index])?;
            index += 1;
            let target = old_start.checked_sub(1).ok_or(())?;
            if target < source_cursor || target > source.len() {
                return Err(());
            }
            for unchanged in &source[source_cursor..target] {
                output.extend_from_slice(unchanged);
            }
            source_cursor = target;
            let mut consumed_old = 0_usize;
            let mut produced_new = 0_usize;
            while index < lines.len()
                && !lines[index].starts_with("@@ ")
                && !lines[index].starts_with("diff --git ")
            {
                let line = lines[index].as_bytes();
                let (marker, bytes) = line.split_first().ok_or(())?;
                match marker {
                    b' ' => {
                        if source.get(source_cursor).copied() != Some(bytes) {
                            return Err(());
                        }
                        output.extend_from_slice(bytes);
                        source_cursor += 1;
                        consumed_old += 1;
                        produced_new += 1;
                    }
                    b'-' => {
                        if source.get(source_cursor).copied() != Some(bytes) {
                            return Err(());
                        }
                        source_cursor += 1;
                        consumed_old += 1;
                    }
                    b'+' => {
                        output.extend_from_slice(bytes);
                        produced_new += 1;
                    }
                    _ => return Err(()),
                }
                index += 1;
            }
            if consumed_old != old_count || produced_new != new_count {
                return Err(());
            }
            let expected_new_start = output[..]
                .split_inclusive(|byte| *byte == b'\n')
                .count()
                .checked_sub(new_count)
                .and_then(|value| value.checked_add(1))
                .ok_or(())?;
            if expected_new_start != new_start {
                return Err(());
            }
        }
        if !saw_hunk {
            return Err(());
        }
        for remaining in source.into_iter().skip(source_cursor) {
            output.extend_from_slice(remaining);
        }
        tree.insert(left.to_owned(), TreeEntry::File(output));
    }
    if touched.is_empty() {
        Err(())
    } else {
        Ok(())
    }
}

fn valid_index_line(line: &str) -> bool {
    let Some(rest) = line.strip_prefix("index ") else {
        return false;
    };
    let Some((hashes, mode)) = rest.split_once(' ') else {
        return false;
    };
    let Some((old, new)) = hashes.split_once("..") else {
        return false;
    };
    mode == "100644"
        && (7..=64).contains(&old.len())
        && (7..=64).contains(&new.len())
        && old.bytes().all(|byte| byte.is_ascii_hexdigit())
        && new.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn split_lines(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.split_inclusive(|byte| *byte == b'\n').collect()
}

fn parse_hunk_header(line: &str) -> Result<(usize, usize, usize, usize), ()> {
    let line = line.strip_suffix('\n').ok_or(())?;
    let body = line
        .strip_prefix("@@ -")
        .and_then(|value| value.strip_suffix(" @@"))
        .ok_or(())?;
    let (old, new) = body.split_once(" +").ok_or(())?;
    let (old_start, old_count) = parse_range(old)?;
    let (new_start, new_count) = parse_range(new)?;
    Ok((old_start, old_count, new_start, new_count))
}

fn parse_range(range: &str) -> Result<(usize, usize), ()> {
    let (start, count) = range.split_once(',').unwrap_or((range, "1"));
    if start.starts_with('0') || count.starts_with('0') {
        return Err(());
    }
    Ok((
        start.parse().map_err(|_| ())?,
        count.parse().map_err(|_| ())?,
    ))
}

fn open_and_hash_archive(path: &Path, spec: ArchiveSpec) -> Result<File, ()> {
    let repo_fd =
        open(repository_root()?, directory_open_flags(), Mode::empty()).map_err(|_| ())?;
    let repo_identity = stat_identity(&fstat(&repo_fd).map_err(|_| ())?)?;
    let mut components = path.components();
    if !matches!(components.next(), Some(Component::RootDir)) {
        return Err(());
    }
    let names = components
        .map(|component| match component {
            Component::Normal(name) => Ok(name.to_os_string()),
            _ => Err(()),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let (file_name, directories) = names.split_last().ok_or(())?;
    let mut current = open("/", directory_open_flags(), Mode::empty()).map_err(|_| ())?;
    if stat_identity(&fstat(&current).map_err(|_| ())?)? == repo_identity {
        return Err(());
    }
    for directory in directories {
        current =
            openat(&current, directory, directory_open_flags(), Mode::empty()).map_err(|_| ())?;
        if stat_identity(&fstat(&current).map_err(|_| ())?)? == repo_identity {
            return Err(());
        }
    }
    let fd = openat(
        &current,
        file_name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|_| ())?;
    let stat = fstat(&fd).map_err(|_| ())?;
    if !FileType::from_raw_mode(stat.st_mode).is_file() {
        return Err(());
    }
    let size = u64::try_from(stat.st_size).map_err(|_| ())?;
    if size != spec.exact_bytes || size > spec.maximum_bytes {
        return Err(());
    }

    let mut file = File::from(fd);
    let actual = hash_reader_exact(&mut file, size)?;
    if actual != spec.sha256 {
        return Err(());
    }
    let final_stat = fstat(&file).map_err(|_| ())?;
    if stat_identity(&final_stat)? != stat_identity(&stat)?
        || !FileType::from_raw_mode(final_stat.st_mode).is_file()
        || u64::try_from(final_stat.st_size).map_err(|_| ())? != size
    {
        return Err(());
    }
    file.seek(SeekFrom::Start(0)).map_err(|_| ())?;
    Ok(file)
}

fn hash_reader_exact(reader: &mut impl Read, exact_bytes: u64) -> Result<[u8; 32], ()> {
    let mut hasher = Sha256::new();
    let mut total = 0_u64;
    let mut chunk = [0_u8; 8192];
    loop {
        let read = reader.read(&mut chunk).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        total = total.checked_add(read as u64).ok_or(())?;
        if total > exact_bytes {
            return Err(());
        }
        hasher.update(&chunk[..read]);
    }
    if total != exact_bytes {
        return Err(());
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
fn decode_single_gzip_member(reader: impl Read, maximum_expanded: usize) -> Result<Vec<u8>, ()> {
    decode_single_gzip_member_cancelled(reader, maximum_expanded, &AtomicUsize::new(ACTIVE))
}

fn decode_single_gzip_member_cancelled(
    reader: impl Read,
    maximum_expanded: usize,
    state: &AtomicUsize,
) -> Result<Vec<u8>, ()> {
    let buffered = BufReader::new(reader);
    let mut decoder = GzDecoder::new(buffered);
    let mut expanded = Vec::new();
    let mut chunk = [0_u8; 8192];
    loop {
        check_active(state)?;
        let read = decoder.read(&mut chunk).map_err(|_| ())?;
        if read == 0 {
            break;
        }
        let next = expanded.len().checked_add(read).ok_or(())?;
        if next > maximum_expanded {
            return Err(());
        }
        expanded.extend_from_slice(&chunk[..read]);
    }

    let mut compressed = decoder.into_inner();
    if !compressed.fill_buf().map_err(|_| ())?.is_empty() {
        return Err(());
    }
    Ok(expanded)
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::{Compression, GzBuilder};
    use rustix::process::{kill_process, Pid, Signal};
    use std::cell::RefCell;
    use std::fs::OpenOptions;
    use std::io::{BufRead, Cursor, Write};
    use std::os::unix::fs::symlink;
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::net::UnixListener;
    use std::rc::Rc;
    use std::sync::{mpsc, Mutex};
    use std::time::{Duration, Instant};

    static WORKSPACE_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn test_lock() -> std::sync::MutexGuard<'static, ()> {
        WORKSPACE_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn gzip(bytes: &[u8]) -> Vec<u8> {
        let mut encoder = GzBuilder::new()
            .mtime(0)
            .operating_system(255)
            .write(Vec::new(), Compression::new(6));
        encoder.write_all(bytes).unwrap();
        encoder.finish().unwrap()
    }

    fn write_octal(field: &mut [u8], value: u64) {
        let digits = format!("{:0width$o}", value, width = field.len() - 1);
        assert_eq!(digits.len(), field.len() - 1);
        field[..digits.len()].copy_from_slice(digits.as_bytes());
        field[field.len() - 1] = 0;
    }

    fn tar_header(path: &str, bytes: &[u8], kind: u8) -> [u8; 512] {
        assert!(path.len() <= 100);
        let mut header = [0_u8; 512];
        header[..path.len()].copy_from_slice(path.as_bytes());
        write_octal(&mut header[100..108], 0o600);
        write_octal(&mut header[108..116], 0);
        write_octal(&mut header[116..124], 0);
        write_octal(&mut header[124..136], bytes.len() as u64);
        write_octal(&mut header[136..148], 0);
        header[148..156].fill(b' ');
        header[156] = kind;
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let checksum_text = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_text.as_bytes());
        header
    }

    fn synthetic_tar() -> Vec<u8> {
        let entries = [
            ("synthetic-0.0.0/LICENSE", b"synthetic license\n".as_slice()),
            ("synthetic-0.0.0/src/message.txt", b"before\n".as_slice()),
        ];
        let mut tar = Vec::new();
        for (path, bytes) in entries {
            tar.extend_from_slice(&tar_header(path, bytes, b'0'));
            tar.extend_from_slice(bytes);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.extend_from_slice(&[0; 1024]);
        tar
    }

    fn tar_from_entries(entries: &[(&str, &[u8], u8)]) -> Vec<u8> {
        let mut tar = Vec::new();
        for (path, bytes, kind) in entries {
            tar.extend_from_slice(&tar_header(path, bytes, *kind));
            tar.extend_from_slice(bytes);
            tar.resize(tar.len().div_ceil(512) * 512, 0);
        }
        tar.extend_from_slice(&[0; 1024]);
        tar
    }

    fn refresh_checksum(header: &mut [u8]) {
        header[148..156].fill(b' ');
        let checksum: u64 = header.iter().map(|byte| u64::from(*byte)).sum();
        let checksum_text = format!("{checksum:06o}\0 ");
        header[148..156].copy_from_slice(checksum_text.as_bytes());
    }

    fn synthetic_fixture() -> tempfile::NamedTempFile {
        let archive = gzip(&synthetic_tar());
        let mut fixture = tempfile::Builder::new()
            .suffix(".crate")
            .tempfile_in(SYSTEM_TEMP)
            .unwrap();
        fixture.write_all(&archive).unwrap();
        fixture.flush().unwrap();
        fixture
    }

    fn external_temp_dir() -> tempfile::TempDir {
        tempfile::Builder::new()
            .prefix("maverick-b002-s2-test-")
            .tempdir_in(SYSTEM_TEMP)
            .unwrap()
    }

    fn current_umask() -> Mode {
        let previous = umask(Mode::RWXG | Mode::RWXO);
        umask(previous);
        previous
    }

    fn parent_is_empty() -> bool {
        std::fs::read_dir(Path::new(SYSTEM_TEMP).join(WORKSPACE_PARENT))
            .map(|entries| entries.count() == 0)
            .unwrap_or(false)
    }

    fn run_disposable_fixture_process() -> ! {
        let fixture = Rc::new(RefCell::new(None));
        let prepare_fixture = Rc::clone(&fixture);
        let cleanup_fixture = Rc::clone(&fixture);
        run_signal_process(
            move || {
                umask(Mode::WGRP | Mode::WOTH);
                let fixture = synthetic_fixture();
                let path = fixture.path().as_os_str().to_owned();
                *prepare_fixture.borrow_mut() = Some(fixture);
                Ok(vec![OsString::from("verifier"), path])
            },
            SYNTHETIC_SPEC,
            move || {
                let Some(fixture) = cleanup_fixture.borrow_mut().take() else {
                    return false;
                };
                let fixture_path = fixture.path().to_owned();
                let probe_path = fixture_path.with_extension("umask-probe");
                let probe_ok = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&probe_path)
                    .and_then(|file| file.metadata())
                    .map(|metadata| metadata.mode() & 0o777 == 0o644)
                    .unwrap_or(false);
                let probe_removed = std::fs::remove_file(&probe_path).is_ok();
                let fixture_removed = fixture.close().is_ok();
                current_umask() == (Mode::WGRP | Mode::WOTH)
                    && parent_is_empty()
                    && probe_ok
                    && probe_removed
                    && fixture_removed
            },
        )
    }

    fn production_binary() -> PathBuf {
        let current = env::current_exe().unwrap();
        let debug = current.parent().unwrap().parent().unwrap();
        debug.join("quiche-fork-replay-verifier")
    }

    fn test_repo_identity() -> (u64, u64) {
        let fd = open(
            repository_root().unwrap(),
            directory_open_flags(),
            Mode::empty(),
        )
        .unwrap();
        stat_identity(&fstat(&fd).unwrap()).unwrap()
    }

    fn wait_for_exit(child: &mut std::process::Child) -> std::process::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("signal child exceeded the bounded watchdog");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn send_signal_after_ready(
        signal: Signal,
        child_test: &'static str,
        child_environment: &'static str,
        ready_marker: &'static str,
    ) {
        let mut child = Command::new(env::current_exe().unwrap())
            .args(["--exact", child_test, "--nocapture", "--test-threads=1"])
            .env(child_environment, "1")
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            let mut line = String::new();
            let mut sent = false;
            while reader.read_line(&mut line).unwrap_or(0) != 0 {
                if !sent && line.contains(ready_marker) {
                    let _ = ready_tx.send(());
                    sent = true;
                }
                line.clear();
            }
        });
        if ready_rx.recv_timeout(Duration::from_secs(10)).is_err() {
            let _ = child.kill();
            let _ = child.wait();
            panic!("signal child never reached the causal barrier");
        }
        kill_process(Pid::from_child(&child), signal).unwrap();
        assert_eq!(wait_for_exit(&mut child).code(), Some(1));
        assert!(parent_is_empty());
    }

    #[test]
    fn generated_fixture_matches_fixed_synthetic_constants() {
        let _lock = test_lock();
        let archive = gzip(&synthetic_tar());
        let mut tree = parse_ustar(&synthetic_tar()).unwrap();
        let initial = tree_manifest_sha256(&tree);
        apply_unified_patch(&mut tree, SYNTHETIC_PATCH, SYNTHETIC_PATCH_ALLOWLIST).unwrap();
        let final_tree = tree_manifest_sha256(&tree);
        assert_eq!(archive.len() as u64, SYNTHETIC_ARCHIVE_BYTES);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(&archive)),
            SYNTHETIC_ARCHIVE_SHA256
        );
        assert_eq!(initial, SYNTHETIC_INITIAL_TREE_SHA256);
        assert_eq!(final_tree, SYNTHETIC_FINAL_TREE_SHA256);
    }

    #[test]
    fn cli_accepts_exactly_one_external_absolute_crate_path() {
        let _lock = test_lock();
        let external = if cfg!(target_os = "macos") {
            "/private/tmp/synthetic.crate"
        } else {
            "/tmp/synthetic.crate"
        };
        let parsed = parse_args([OsString::from("verifier"), OsString::from(external)]).unwrap();
        assert_eq!(parsed, PathBuf::from(external));

        assert!(parse_args([OsString::from("verifier")]).is_err());
        assert!(parse_args([
            OsString::from("verifier"),
            OsString::from(external),
            OsString::from("extra")
        ])
        .is_err());
        assert!(
            parse_args([OsString::from("verifier"), OsString::from("relative.crate")]).is_err()
        );
    }

    #[test]
    fn workspace_base_ancestor_walk_rejects_the_repository_identity() {
        let _lock = test_lock();
        let base_fd = open(SYSTEM_TEMP, directory_open_flags(), Mode::empty()).unwrap();
        let base = fstat(&base_fd).unwrap();
        let base_identity = stat_identity(&base).unwrap();
        assert!(validate_workspace_base(&base_fd, &base, base_identity, base_identity).is_err());

        let root_fd = open("/", directory_open_flags(), Mode::empty()).unwrap();
        let root_identity = stat_identity(&fstat(&root_fd).unwrap()).unwrap();
        assert!(validate_workspace_base(&base_fd, &base, base_identity, root_identity).is_err());
        assert!(
            validate_workspace_base(&base_fd, &base, base_identity, test_repo_identity()).is_ok()
        );
    }

    #[test]
    fn directory_creation_reserves_the_descriptor_needed_for_identity_binding() {
        let _lock = test_lock();
        let state = AtomicUsize::new(ACTIVE);
        let mut mask = UmaskGuard::install();
        RESERVE_DESCRIPTOR_TEST_FAILURE.store(true, Ordering::Release);
        assert!(Workspace::create(test_repo_identity(), &state).is_err());
        RESERVE_DESCRIPTOR_TEST_FAILURE.store(false, Ordering::Release);
        mask.restore();
        assert!(parent_is_empty());
    }

    #[test]
    fn gzip_accepts_one_member_and_rejects_trailing_or_concatenated_bytes() {
        let _lock = test_lock();
        let first = gzip(b"bounded synthetic bytes");
        assert_eq!(
            decode_single_gzip_member(Cursor::new(&first), 64).unwrap(),
            b"bounded synthetic bytes"
        );

        let mut trailing = first.clone();
        trailing.push(1);
        assert!(decode_single_gzip_member(Cursor::new(trailing), 64).is_err());

        let mut concatenated = first;
        concatenated.extend_from_slice(&gzip(b"second member"));
        assert!(decode_single_gzip_member(Cursor::new(concatenated), 64).is_err());

        let mut corrupted = gzip(b"bounded synthetic bytes");
        let middle = corrupted.len() / 2;
        corrupted[middle] ^= 1;
        assert!(decode_single_gzip_member(Cursor::new(corrupted), 64).is_err());

        let mut truncated = gzip(b"bounded synthetic bytes");
        truncated.pop();
        assert!(decode_single_gzip_member(Cursor::new(truncated), 64).is_err());
    }

    #[test]
    fn archive_path_walk_rejects_links_nonfiles_sizes_and_repository_aliases() {
        let _lock = test_lock();
        let directory = external_temp_dir();
        let archive = gzip(&synthetic_tar());
        let spec = ArchiveSpec {
            exact_bytes: archive.len() as u64,
            maximum_bytes: MAX_ARCHIVE_BYTES,
            sha256: Sha256::digest(&archive).into(),
        };

        let real = directory.path().join("real.crate");
        std::fs::write(&real, &archive).unwrap();
        let final_link = directory.path().join("final-link.crate");
        symlink(&real, &final_link).unwrap();
        assert!(open_and_hash_archive(&final_link, spec).is_err());

        let real_directory = directory.path().join("real-directory");
        std::fs::create_dir(&real_directory).unwrap();
        std::fs::write(real_directory.join("nested.crate"), &archive).unwrap();
        let directory_link = directory.path().join("directory-link");
        symlink(&real_directory, &directory_link).unwrap();
        assert!(open_and_hash_archive(&directory_link.join("nested.crate"), spec).is_err());

        let directory_input = directory.path().join("directory.crate");
        std::fs::create_dir(&directory_input).unwrap();
        assert!(open_and_hash_archive(&directory_input, spec).is_err());
        let socket_input = directory.path().join("socket.crate");
        let _socket = UnixListener::bind(&socket_input).unwrap();
        assert!(open_and_hash_archive(&socket_input, spec).is_err());

        let wrong_size = directory.path().join("wrong-size.crate");
        std::fs::write(&wrong_size, [0_u8; 1]).unwrap();
        assert!(open_and_hash_archive(&wrong_size, spec).is_err());
        let oversized = directory.path().join("oversized.crate");
        File::create(&oversized)
            .unwrap()
            .set_len(MAX_ARCHIVE_BYTES + 1)
            .unwrap();
        let oversized_spec = ArchiveSpec {
            exact_bytes: MAX_ARCHIVE_BYTES + 1,
            maximum_bytes: MAX_ARCHIVE_BYTES,
            sha256: [0; 32],
        };
        assert!(open_and_hash_archive(&oversized, oversized_spec).is_err());

        let repo = repository_root().unwrap();
        assert!(open_and_hash_archive(&repo.join("Cargo.lock"), spec).is_err());
        let case_alias = PathBuf::from(repo.as_os_str().to_string_lossy().to_ascii_uppercase())
            .join("Cargo.lock");
        assert!(open_and_hash_archive(&case_alias, spec).is_err());
    }

    #[test]
    fn archive_fd_survives_path_swap_and_rejects_same_inode_mutation() {
        let _lock = test_lock();
        let directory = external_temp_dir();
        let archive = gzip(&synthetic_tar());
        let spec = ArchiveSpec {
            exact_bytes: archive.len() as u64,
            maximum_bytes: MAX_ARCHIVE_BYTES,
            sha256: Sha256::digest(&archive).into(),
        };

        let swapped = directory.path().join("swapped.crate");
        std::fs::write(&swapped, &archive).unwrap();
        let input = open_and_hash_archive(&swapped, spec).unwrap();
        std::fs::rename(&swapped, directory.path().join("original.crate")).unwrap();
        std::fs::write(&swapped, vec![0_u8; archive.len()]).unwrap();
        let mut mask = UmaskGuard::install();
        assert!(
            replay_worker(input, spec, test_repo_identity(), &AtomicUsize::new(ACTIVE)).is_ok()
        );
        mask.restore();
        assert!(parent_is_empty());

        let mutated = directory.path().join("mutated.crate");
        std::fs::write(&mutated, &archive).unwrap();
        let input = open_and_hash_archive(&mutated, spec).unwrap();
        let mut changed = archive.clone();
        changed[0] ^= 1;
        let mut writer = OpenOptions::new().write(true).open(&mutated).unwrap();
        writer.write_all(&changed).unwrap();
        writer.flush().unwrap();
        drop(writer);
        let mut mask = UmaskGuard::install();
        assert!(
            replay_worker(input, spec, test_repo_identity(), &AtomicUsize::new(ACTIVE)).is_err()
        );
        mask.restore();
        assert!(parent_is_empty());
    }

    #[test]
    fn gzip_expansion_limit_is_checked_before_tree_replay() {
        let _lock = test_lock();
        let compressed = gzip(&[7; 65]);
        assert!(decode_single_gzip_member(Cursor::new(compressed), 64).is_err());
    }

    #[test]
    fn strict_ustar_accepts_the_synthetic_tree_and_rejects_unsafe_shapes() {
        let _lock = test_lock();
        let tar = synthetic_tar();
        let tree = parse_ustar(&tar).unwrap();
        assert_eq!(
            tree.get("synthetic-0.0.0/src/message.txt"),
            Some(&TreeEntry::File(b"before\n".to_vec()))
        );

        let mut gnu = tar_from_entries(&[("gnu-file", b"gnu bytes", b'0')]);
        gnu[257..263].copy_from_slice(b"ustar ");
        gnu[263..265].copy_from_slice(b" \0");
        refresh_checksum(&mut gnu[..512]);
        assert_eq!(
            parse_ustar(&gnu).unwrap().get("gnu-file"),
            Some(&TreeEntry::File(b"gnu bytes".to_vec()))
        );

        let explicit_directory =
            tar_from_entries(&[("explicit", b"", b'5'), ("explicit/file", b"bytes", b'0')]);
        let explicit_tree = parse_ustar(&explicit_directory).unwrap();
        assert_eq!(explicit_tree.get("explicit"), Some(&TreeEntry::Directory));
        assert_eq!(
            explicit_tree.get("explicit/file"),
            Some(&TreeEntry::File(b"bytes".to_vec()))
        );

        let mut posix_prefix = tar_from_entries(&[("file", b"prefixed", b'0')]);
        posix_prefix[345..351].copy_from_slice(b"prefix");
        refresh_checksum(&mut posix_prefix[..512]);
        assert_eq!(
            parse_ustar(&posix_prefix).unwrap().get("prefix/file"),
            Some(&TreeEntry::File(b"prefixed".to_vec()))
        );

        let mut bad_checksum = tar.clone();
        bad_checksum[0] ^= 1;
        assert!(parse_ustar(&bad_checksum).is_err());

        let mut symlink = tar.clone();
        symlink[156] = b'2';
        refresh_checksum(&mut symlink[..512]);
        assert!(parse_ustar(&symlink).is_err());

        let mut traversal = tar.clone();
        traversal[..3].copy_from_slice(b"../");
        refresh_checksum(&mut traversal[..512]);
        assert!(parse_ustar(&traversal).is_err());

        let mut nonzero_tail = tar;
        nonzero_tail.extend_from_slice(&[0; 512]);
        *nonzero_tail.last_mut().unwrap() = 1;
        assert!(parse_ustar(&nonzero_tail).is_err());

        let duplicate = tar_from_entries(&[("same", b"one", b'0'), ("same", b"two", b'0')]);
        assert!(parse_ustar(&duplicate).is_err());
        let inferred_collision = tar_from_entries(&[("a/file", b"one", b'0'), ("a", b"", b'5')]);
        assert!(parse_ustar(&inferred_collision).is_err());
        let file_then_child = tar_from_entries(&[("a", b"one", b'0'), ("a/file", b"two", b'0')]);
        assert!(parse_ustar(&file_then_child).is_err());
        let casefold_collision =
            tar_from_entries(&[("A/file", b"one", b'0'), ("a/other", b"two", b'0')]);
        assert!(parse_ustar(&casefold_collision).is_err());

        for kind in *b"123467xgLKS" {
            assert!(parse_ustar(&tar_from_entries(&[("unsafe", b"", kind)])).is_err());
        }

        for index in [157_usize, 329, 500] {
            let mut metadata = synthetic_tar();
            metadata[index] = 1;
            refresh_checksum(&mut metadata[..512]);
            assert!(parse_ustar(&metadata).is_err());
        }
        let mut base256 = synthetic_tar();
        base256[124] = 0x80;
        refresh_checksum(&mut base256[..512]);
        assert!(parse_ustar(&base256).is_err());
        let mut nonzero_padding = synthetic_tar();
        nonzero_padding[512 + b"synthetic license\n".len()] = 1;
        assert!(parse_ustar(&nonzero_padding).is_err());
        let mut bad_magic = synthetic_tar();
        bad_magic[257] = b'X';
        refresh_checksum(&mut bad_magic[..512]);
        assert!(parse_ustar(&bad_magic).is_err());

        let oversized = vec![7; MAX_FILE_BYTES + 1];
        assert!(parse_ustar(&tar_from_entries(&[("large", &oversized, b'0')])).is_err());
        let many_headers = (0..=MAX_TAR_ENTRIES)
            .map(|index| (format!("entry-{index}"), b"x".as_slice(), b'0'))
            .collect::<Vec<_>>();
        let many_header_refs = many_headers
            .iter()
            .map(|(path, bytes, kind)| (path.as_str(), *bytes, *kind))
            .collect::<Vec<_>>();
        assert!(parse_ustar(&tar_from_entries(&many_header_refs)).is_err());
        let many_tree_entries = (0..33)
            .map(|index| (format!("dir-{index}/file"), b"x".as_slice(), b'0'))
            .collect::<Vec<_>>();
        let many_tree_refs = many_tree_entries
            .iter()
            .map(|(path, bytes, kind)| (path.as_str(), *bytes, *kind))
            .collect::<Vec<_>>();
        assert!(parse_ustar(&tar_from_entries(&many_tree_refs)).is_err());
    }

    #[test]
    fn patch_applies_at_exact_lines_without_offset_fuzz_or_replay() {
        let _lock = test_lock();
        let mut tree = parse_ustar(&synthetic_tar()).unwrap();
        apply_unified_patch(&mut tree, SYNTHETIC_PATCH, SYNTHETIC_PATCH_ALLOWLIST).unwrap();
        assert_eq!(
            tree.get("synthetic-0.0.0/src/message.txt"),
            Some(&TreeEntry::File(b"after\n".to_vec()))
        );
        assert!(
            apply_unified_patch(&mut tree, SYNTHETIC_PATCH, SYNTHETIC_PATCH_ALLOWLIST).is_err()
        );

        let mut offset = parse_ustar(&synthetic_tar()).unwrap();
        let changed = String::from_utf8(SYNTHETIC_PATCH.to_vec())
            .unwrap()
            .replace("@@ -1 +1 @@", "@@ -2 +2 @@");
        assert!(
            apply_unified_patch(&mut offset, changed.as_bytes(), SYNTHETIC_PATCH_ALLOWLIST)
                .is_err()
        );

        let mut unexpected = parse_ustar(&synthetic_tar()).unwrap();
        assert!(apply_unified_patch(&mut unexpected, SYNTHETIC_PATCH, &["other.txt"]).is_err());
    }

    #[test]
    fn fd_anchored_workspace_copies_and_cleans_the_exact_private_archive() {
        let _lock = test_lock();
        let archive = gzip(&synthetic_tar());
        let spec = ArchiveSpec {
            exact_bytes: archive.len() as u64,
            maximum_bytes: MAX_ARCHIVE_BYTES,
            sha256: Sha256::digest(&archive).into(),
        };
        let mut fixture = tempfile::Builder::new()
            .suffix(".crate")
            .tempfile_in(SYSTEM_TEMP)
            .unwrap();
        fixture.write_all(&archive).unwrap();
        fixture.flush().unwrap();

        let mut input = open_and_hash_archive(fixture.path(), spec).unwrap();
        let mut mask = UmaskGuard::install();
        let state = AtomicUsize::new(ACTIVE);
        let mut workspace = Workspace::create(test_repo_identity(), &state).unwrap();
        let private = workspace.copy_archive(&mut input, spec, &state).unwrap();
        assert_eq!(private, archive);
        assert_eq!(workspace.ledger.len(), 1);
        assert_eq!(workspace.ledger[0].path, PRIVATE_ARCHIVE);
        assert_eq!(workspace.ledger[0].kind, LedgerKind::File);
        workspace.cleanup().unwrap();
        mask.restore();

        let parent = Path::new(SYSTEM_TEMP).join(WORKSPACE_PARENT);
        assert_eq!(std::fs::read_dir(parent).unwrap().count(), 0);
    }

    #[test]
    fn private_copy_rehash_is_bounded_and_rejects_concurrent_append() {
        let _lock = test_lock();
        let archive = gzip(&synthetic_tar());
        let spec = ArchiveSpec {
            exact_bytes: archive.len() as u64,
            maximum_bytes: MAX_ARCHIVE_BYTES,
            sha256: Sha256::digest(&archive).into(),
        };
        let mut fixture = tempfile::Builder::new()
            .suffix(".crate")
            .tempfile_in(SYSTEM_TEMP)
            .unwrap();
        fixture.write_all(&archive).unwrap();
        fixture.flush().unwrap();
        let mut input = open_and_hash_archive(fixture.path(), spec).unwrap();
        let mut mask = UmaskGuard::install();
        let state = AtomicUsize::new(ACTIVE);
        let mut workspace = Workspace::create(test_repo_identity(), &state).unwrap();

        PRIVATE_REHASH_TEST_BARRIER_READY.store(false, Ordering::Release);
        PRIVATE_REHASH_TEST_BARRIER_RELEASE.store(false, Ordering::Release);
        PRIVATE_REHASH_TEST_BARRIER_ENABLED.store(true, Ordering::Release);
        let private_path = Path::new(SYSTEM_TEMP)
            .join(WORKSPACE_PARENT)
            .join(WORKSPACE_CHILD)
            .join(PRIVATE_ARCHIVE);
        let mutator = std::thread::spawn(move || {
            while !PRIVATE_REHASH_TEST_BARRIER_READY.load(Ordering::Acquire) {
                std::hint::spin_loop();
            }
            let mut private = OpenOptions::new().append(true).open(private_path).unwrap();
            private
                .write_all(&vec![7; MAX_ARCHIVE_BYTES as usize])
                .unwrap();
            private.flush().unwrap();
            PRIVATE_REHASH_TEST_BARRIER_RELEASE.store(true, Ordering::Release);
        });
        assert!(workspace.copy_archive(&mut input, spec, &state).is_err());
        mutator.join().unwrap();
        PRIVATE_REHASH_TEST_BARRIER_ENABLED.store(false, Ordering::Release);
        workspace.cleanup().unwrap();
        mask.restore();
        assert!(parent_is_empty());
    }

    #[test]
    fn invalid_archive_remains_red() {
        let _lock = test_lock();
        assert!(verify(Path::new("/does/not/exist.crate"), SYNTHETIC_SPEC).is_err());
    }

    #[test]
    fn fixed_synthetic_fixture_passes_the_replay_worker() {
        let _lock = test_lock();
        let fixture = synthetic_fixture();
        let input = open_and_hash_archive(fixture.path(), SYNTHETIC_SPEC).unwrap();
        let mut mask = UmaskGuard::install();
        assert!(replay_worker(
            input,
            SYNTHETIC_SPEC,
            test_repo_identity(),
            &AtomicUsize::new(ACTIVE)
        )
        .is_ok());
        mask.restore();
    }

    #[test]
    fn fixed_git_commit_tree_blob_chain_is_read_as_exact_raw_bytes() {
        let _lock = test_lock();
        read_fixed_git_chain(&repository_root().unwrap()).unwrap();
    }

    #[test]
    fn prebuilt_production_binary_has_exact_silent_success_and_failure() {
        let _lock = test_lock();
        let binary = production_binary();
        assert!(binary.is_file());
        let fixture = synthetic_fixture();
        let success = Command::new(&binary)
            .arg(fixture.path())
            .current_dir(repository_root().unwrap())
            .env_clear()
            .output()
            .unwrap();
        assert!(success.status.success());
        assert!(success.stdout.is_empty());
        assert!(success.stderr.is_empty());
        assert!(parent_is_empty());

        let red = Command::new(binary)
            .arg("relative.crate")
            .current_dir(repository_root().unwrap())
            .env_clear()
            .output()
            .unwrap();
        assert!(!red.status.success());
        assert!(red.stdout.is_empty());
        assert!(red.stderr.is_empty());
    }

    #[test]
    fn registration_failure_child() {
        let _lock = test_lock();
        if env::var_os("MAVERICK_B002_S2_REGISTER_FAILURE_AT").is_none() {
            return;
        }
        run_signal_process(
            || {
                Ok(vec![
                    OsString::from("verifier"),
                    OsString::from("relative.crate"),
                ])
            },
            SYNTHETIC_SPEC,
            || true,
        )
    }

    #[test]
    fn every_partial_registration_failure_rolls_back_then_exits_red() {
        let _lock = test_lock();
        for index in 0..3 {
            let output = Command::new(env::current_exe().unwrap())
                .args([
                    "--exact",
                    "tests::registration_failure_child",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("MAVERICK_B002_S2_REGISTER_FAILURE_AT", index.to_string())
                .output()
                .unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(output.stderr.is_empty());
        }
    }

    #[test]
    fn catchable_signal_child() {
        let _lock = test_lock();
        if env::var_os("MAVERICK_B002_S2_SIGNAL_CHILD").is_none() {
            return;
        }
        run_disposable_fixture_process()
    }

    #[test]
    fn int_term_and_hup_cancel_before_final_manifest_and_cleanup() {
        let _lock = test_lock();
        for signal in [Signal::INT, Signal::TERM, Signal::HUP] {
            send_signal_after_ready(
                signal,
                "tests::catchable_signal_child",
                "MAVERICK_B002_S2_SIGNAL_CHILD",
                "B-002-S2-BEFORE-FINAL-MANIFEST-READY",
            );
        }
    }

    #[test]
    fn post_cleanup_signal_child() {
        let _lock = test_lock();
        if env::var_os("MAVERICK_B002_S2_POST_CLEANUP_SIGNAL_CHILD").is_none() {
            return;
        }
        run_disposable_fixture_process()
    }

    #[test]
    fn int_term_and_hup_cancel_after_cleanup_before_success_commit() {
        let _lock = test_lock();
        for signal in [Signal::INT, Signal::TERM, Signal::HUP] {
            send_signal_after_ready(
                signal,
                "tests::post_cleanup_signal_child",
                "MAVERICK_B002_S2_POST_CLEANUP_SIGNAL_CHILD",
                "B-002-S2-POST-CLEANUP-READY",
            );
        }
    }

    #[test]
    fn panic_cleanup_child() {
        let _lock = test_lock();
        if env::var_os("MAVERICK_B002_S2_PANIC_CHILD").is_none() {
            return;
        }
        run_disposable_fixture_process()
    }

    #[test]
    fn worker_panic_after_final_manifest_is_private_and_cleans_the_exact_workspace() {
        let _lock = test_lock();
        let output = Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::panic_cleanup_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("MAVERICK_B002_S2_PANIC_CHILD", "1")
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        for bytes in [&output.stdout[..], &output.stderr[..]] {
            assert!(!bytes
                .windows(b"private/example/path".len())
                .any(|window| { window == b"private/example/path" }));
            assert!(!bytes
                .windows(b"secret@example.invalid".len())
                .any(|window| window == b"secret@example.invalid"));
        }
        assert!(parent_is_empty());
    }
}
