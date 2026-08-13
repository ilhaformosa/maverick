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

const MAX_ARCHIVE_BYTES: u64 = 453_798;
const MAX_EXPANDED_BYTES: usize = 2_748_928;
const MAX_TAR_ENTRIES: usize = 87;
const MAX_TREE_ENTRIES: usize = 101;
const MAX_FILE_BYTES: usize = 417_981;
const MAX_PATH_BYTES: usize = 240;
const MAX_GIT_TREE_OBJECT_BYTES: usize = 16_384;
const MAX_GIT_TREE_DEPTH: usize = 16;
const WORKSPACE_PARENT: &str = "maverick-b002-s2-replay";
const WORKSPACE_CHILD: &str = "run";
const PRIVATE_ARCHIVE: &str = "input.crate";
const HISTORICAL_P1_P2_COMMIT_OID: &str = "65157042427a8c803ded724e30bfd2c05a5647f9";
const HISTORICAL_P1_P2_COMMIT_BYTES: usize = 314;
const HISTORICAL_P1_P2_COMMIT_SHA256: [u8; 32] = [
    0xda, 0xb1, 0x78, 0x46, 0x93, 0x18, 0xd5, 0x5c, 0xaa, 0xa3, 0xcc, 0x5e, 0x30, 0x4c, 0x0e, 0x32,
    0xcf, 0x68, 0x79, 0x51, 0x8c, 0x8c, 0x75, 0x5b, 0x93, 0x32, 0xa0, 0x11, 0x7b, 0x28, 0xad, 0x8a,
];
const HISTORICAL_P1_P2_ROOT_TREE_OID: &str = "d3fea12edeede8a6c818a04aef43626a98c2b902";
const HISTORICAL_P1_P2_ROOT_TREE_BYTES: usize = 950;
const HISTORICAL_P1_P2_ROOT_TREE_SHA256: [u8; 32] = [
    0x31, 0x28, 0xaa, 0x71, 0x9a, 0x9a, 0x70, 0xe1, 0x08, 0x73, 0x37, 0xe6, 0xdc, 0x6c, 0x71, 0xa0,
    0xa7, 0xfc, 0xba, 0xfe, 0xd8, 0xce, 0xf6, 0xe1, 0xe0, 0x0c, 0xa2, 0xbf, 0x94, 0x09, 0x5a, 0xa4,
];
const HISTORICAL_P1_P2_VENDOR_TREE_OID: &str = "0bea2c94e4a85a71ad7f0ff174209b7fbfe63355";
const HISTORICAL_P1_P2_VENDOR_TREE_BYTES: usize = 40;
const HISTORICAL_P1_P2_VENDOR_TREE_SHA256: [u8; 32] = [
    0x34, 0x93, 0x83, 0x70, 0xd8, 0x2b, 0x32, 0x93, 0x2e, 0x42, 0xbe, 0x97, 0xa2, 0xa0, 0x1a, 0x8d,
    0x7f, 0x58, 0x9a, 0x35, 0xef, 0x45, 0x36, 0x3d, 0x8f, 0x58, 0xd6, 0xc7, 0x87, 0x7c, 0x56, 0x21,
];
const HISTORICAL_P1_P2_QUICHE_TREE_OID: &str = "fde2f811fab90101e79bf56101e7de262f051c2f";
const HISTORICAL_P1_P2_QUICHE_TREE_BYTES: usize = 306;
const HISTORICAL_P1_P2_QUICHE_TREE_SHA256: [u8; 32] = [
    0x9b, 0xed, 0x3e, 0x03, 0xc5, 0x1f, 0x7f, 0x2f, 0x44, 0x77, 0x61, 0xb0, 0x10, 0x65, 0x34, 0x1a,
    0xfd, 0xae, 0xd1, 0xa3, 0xd8, 0xe1, 0xd1, 0xdc, 0xe2, 0x7e, 0xd8, 0x72, 0x24, 0xf0, 0x13, 0x41,
];
const HISTORICAL_P1_P2_PATCH_TREE_OID: &str = "31ed89feee0b43549d3ebafbf7119b926e40787d";
const HISTORICAL_P1_P2_PATCH_TREE_BYTES: usize = 141;
const HISTORICAL_P1_P2_PATCH_TREE_SHA256: [u8; 32] = [
    0x34, 0xa8, 0x55, 0xb6, 0x85, 0xf4, 0x09, 0x4a, 0xbb, 0xea, 0x16, 0x25, 0x55, 0xa8, 0x69, 0x32,
    0x24, 0x86, 0x08, 0x17, 0x37, 0x4c, 0x03, 0x54, 0x75, 0x39, 0x64, 0x4a, 0x5d, 0x78, 0x76, 0x13,
];
const HISTORICAL_P3_COMMIT_OID: &str = "596da6ef9b33434b392d6440baf8d4313dd49751";
const HISTORICAL_P3_COMMIT_BYTES: usize = 310;
const HISTORICAL_P3_COMMIT_SHA256: [u8; 32] = [
    0x3b, 0xf1, 0xe9, 0x1a, 0x8d, 0xe4, 0x57, 0x86, 0x62, 0x96, 0x75, 0x11, 0x44, 0x04, 0x20, 0xff,
    0x65, 0x9e, 0x2b, 0x03, 0x9e, 0xf2, 0xd2, 0xee, 0xfa, 0xf9, 0x71, 0x8d, 0x71, 0xed, 0xa8, 0xb9,
];
const HISTORICAL_P3_ROOT_TREE_OID: &str = "3a52324c6483c853a6f777f06bc8232ecd388d2d";
const HISTORICAL_P3_ROOT_TREE_BYTES: usize = 950;
const HISTORICAL_P3_ROOT_TREE_SHA256: [u8; 32] = [
    0x2e, 0x2c, 0x13, 0x56, 0x21, 0x4a, 0x28, 0x9d, 0xd4, 0xe5, 0x41, 0xc6, 0xd0, 0x66, 0xb3, 0x6b,
    0x3e, 0x06, 0xbe, 0x91, 0x3d, 0x47, 0xfb, 0x45, 0x9a, 0xac, 0xd9, 0x72, 0xfc, 0x2d, 0x72, 0x46,
];
const HISTORICAL_FINAL_COMMIT_OID: &str = "40b0aa7b630c0decc411c0983795828d15252bda";
const HISTORICAL_FINAL_COMMIT_BYTES: usize = 308;
const HISTORICAL_FINAL_COMMIT_SHA256: [u8; 32] = [
    0xf1, 0xd3, 0x52, 0xfb, 0x26, 0x0c, 0xa2, 0x8d, 0x6e, 0x35, 0x1e, 0x25, 0xe8, 0x2d, 0x98, 0xcf,
    0xed, 0x7b, 0x36, 0x1f, 0x87, 0xc1, 0xc1, 0x17, 0x3a, 0xdf, 0x53, 0x27, 0xf9, 0xd4, 0x22, 0x8a,
];
const HISTORICAL_FINAL_ROOT_TREE_OID: &str = "e57322e1467d84dbeb9c920269c64635b465efa9";
const HISTORICAL_FINAL_ROOT_TREE_BYTES: usize = 950;
const HISTORICAL_FINAL_ROOT_TREE_SHA256: [u8; 32] = [
    0xe2, 0x64, 0x8e, 0x17, 0x77, 0xf3, 0xde, 0xf2, 0x8e, 0x1c, 0xe0, 0x4a, 0x86, 0x12, 0xf5, 0xef,
    0x57, 0x6b, 0xfc, 0xb8, 0xda, 0xf8, 0xf2, 0x24, 0xfb, 0xe7, 0xd2, 0x1e, 0x8d, 0xc5, 0x1d, 0x55,
];
const HISTORICAL_FINAL_VENDOR_TREE_OID: &str = "a61cb7f7f64fc8ee97a848da0c78143a035f613f";
const HISTORICAL_FINAL_VENDOR_TREE_BYTES: usize = 40;
const HISTORICAL_FINAL_VENDOR_TREE_SHA256: [u8; 32] = [
    0x6a, 0x5e, 0x91, 0xd6, 0xa4, 0x03, 0x3a, 0xbc, 0xb1, 0x1a, 0xfe, 0x65, 0xe8, 0xd4, 0xb6, 0x16,
    0x72, 0x3a, 0x19, 0x3e, 0x3e, 0x4d, 0x46, 0x2f, 0x99, 0xec, 0xe2, 0x50, 0x26, 0xb0, 0x88, 0x19,
];
const HISTORICAL_FINAL_QUICHE_TREE_OID: &str = "79e628882099575a6b9f9d10fa3a12571dff9677";
const HISTORICAL_FINAL_QUICHE_TREE_BYTES: usize = 306;
const HISTORICAL_FINAL_QUICHE_TREE_SHA256: [u8; 32] = [
    0x13, 0x6a, 0x54, 0xac, 0x22, 0xa2, 0x83, 0x0e, 0x14, 0x44, 0xbf, 0x7a, 0x53, 0x57, 0x72, 0x58,
    0xe3, 0x9f, 0x8b, 0x6b, 0x39, 0xbb, 0x61, 0x12, 0xb5, 0x76, 0xa9, 0xc2, 0x21, 0x49, 0x00, 0x89,
];
const HISTORICAL_FINAL_PATCH_TREE_OID: &str = "8e28afdb1c096a976c1c93bdacda65032cf3900a";
const HISTORICAL_FINAL_PATCH_TREE_BYTES: usize = 200;
const HISTORICAL_FINAL_PATCH_TREE_SHA256: [u8; 32] = [
    0x97, 0xf4, 0x8c, 0x31, 0x70, 0x90, 0x98, 0x02, 0xdb, 0x24, 0x23, 0x43, 0x93, 0x05, 0x8d, 0x76,
    0x7f, 0x71, 0xec, 0x2b, 0x53, 0x35, 0x59, 0x2d, 0xfe, 0x3e, 0x58, 0xc9, 0xe0, 0x43, 0xd2, 0x41,
];
const HISTORICAL_P1_BLOB_OID: &str = "387ff8d539e68d5bcdf21b1b8d4a3e1145b8952a";
const HISTORICAL_P1_BLOB_BYTES: usize = 7164;
const HISTORICAL_P1_BLOB_SHA256: [u8; 32] = [
    0x74, 0xe9, 0x07, 0x8d, 0x2e, 0x6c, 0x24, 0x4b, 0x4f, 0xba, 0x2d, 0xba, 0xd1, 0x85, 0xa8, 0xeb,
    0x1a, 0xdb, 0xa6, 0x76, 0x2d, 0x32, 0x28, 0x65, 0x40, 0xed, 0x64, 0x51, 0x22, 0xbe, 0x04, 0xfa,
];
const HISTORICAL_P2_BLOB_OID: &str = "a2c982213c564e4556399c9aafa2b211fdfadcfc";
const HISTORICAL_P2_BLOB_BYTES: usize = 1268;
const HISTORICAL_P2_BLOB_SHA256: [u8; 32] = [
    0x87, 0x3b, 0xa9, 0x2b, 0x49, 0x8b, 0xa2, 0x60, 0xae, 0x09, 0x7c, 0x47, 0x47, 0x4d, 0x51, 0xee,
    0x79, 0xd6, 0xf9, 0x4a, 0xc8, 0x7e, 0xfa, 0x3b, 0xa5, 0x33, 0x37, 0xca, 0x57, 0x40, 0x45, 0x12,
];
const HISTORICAL_P3_BLOB_OID: &str = "a7fa42323e27fd414f8664d6875f658183313cc5";
const HISTORICAL_P3_BLOB_BYTES: usize = 18_868;
const HISTORICAL_P3_BLOB_SHA256: [u8; 32] = [
    0x92, 0x3c, 0x9c, 0xe8, 0x76, 0xe7, 0x6c, 0x77, 0x58, 0xec, 0xeb, 0xe8, 0xd9, 0x12, 0x65, 0x72,
    0xa2, 0x45, 0xea, 0x98, 0x01, 0x9b, 0x46, 0x7b, 0x66, 0xd5, 0xac, 0xc2, 0x28, 0xad, 0x2e, 0xe0,
];

#[cfg(test)]
const SYNTHETIC_GIT_COMMIT_OID: &str = "f946953e504032c3e8d74b172aba4c27a22dff7b";
#[cfg(test)]
const SYNTHETIC_GIT_COMMIT_BYTES: usize = 1100;
#[cfg(test)]
const SYNTHETIC_GIT_COMMIT_SHA256: [u8; 32] = [
    0x23, 0xf2, 0xc3, 0xe2, 0x74, 0x22, 0x11, 0x83, 0x8b, 0x71, 0x1b, 0x3e, 0x59, 0x54, 0xa0, 0x15,
    0x63, 0x29, 0x30, 0x7f, 0x59, 0xbd, 0x2f, 0x65, 0xa2, 0x22, 0xd9, 0x51, 0xc9, 0x4a, 0x57, 0xac,
];
#[cfg(test)]
const SYNTHETIC_GIT_TREE_OID: &str = "85775ab0088327b78c26db38cda26aad52c50596";
#[cfg(test)]
const SYNTHETIC_GIT_TREE_BYTES: usize = 917;
#[cfg(test)]
const SYNTHETIC_GIT_TREE_SHA256: [u8; 32] = [
    0x6d, 0x8f, 0x91, 0x58, 0xf2, 0x5d, 0x42, 0x24, 0xd1, 0x41, 0x7d, 0xf2, 0x35, 0x6b, 0x19, 0x2d,
    0xc5, 0xed, 0xf8, 0x88, 0xdd, 0x80, 0xb2, 0x71, 0xd9, 0xa4, 0xc9, 0x5f, 0x30, 0x80, 0x91, 0xbc,
];
#[cfg(test)]
const SYNTHETIC_GIT_BLOB_OID: &str = "010f002cf56497ce0a1b4ac124a2e2d86a97bc3d";
#[cfg(test)]
const SYNTHETIC_GIT_BLOB_BYTES: usize = 86;
#[cfg(test)]
const SYNTHETIC_GIT_BLOB_SHA256: [u8; 32] = [
    0x55, 0x9f, 0x48, 0x8c, 0x18, 0x1e, 0x0e, 0x9e, 0x77, 0xcf, 0x17, 0xc2, 0x9d, 0xe6, 0x63, 0x97,
    0x7f, 0x03, 0x6e, 0xc7, 0xff, 0x2e, 0x20, 0x60, 0x58, 0x57, 0x14, 0xbf, 0x53, 0xc5, 0x2d, 0x62,
];

#[cfg(target_os = "macos")]
const SYSTEM_TEMP: &str = "/private/tmp";
#[cfg(target_os = "linux")]
const SYSTEM_TEMP: &str = "/tmp";

#[cfg(test)]
const SYNTHETIC_PATCH: &[u8] =
    b"diff --git a/synthetic-0.0.0/src/message.txt b/synthetic-0.0.0/src/message.txt\n\
index 1111111..2222222 100644\n\
--- a/synthetic-0.0.0/src/message.txt\n\
+++ b/synthetic-0.0.0/src/message.txt\n\
@@ -1 +1 @@\n\
-before\n\
+after\n";
#[cfg(test)]
const SYNTHETIC_PATCH_ALLOWLIST: &[&str] = &["synthetic-0.0.0/src/message.txt"];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PatchWorkingDirectory {
    Vendor,
    StagingRoot,
}

#[derive(Clone, Copy)]
struct PatchApplicationSpec {
    working_directory: PatchWorkingDirectory,
    strip_level: u8,
    index_policy: IndexPolicy,
}

struct HistoricalPatchSpec {
    application: PatchApplicationSpec,
    allowlist: &'static [&'static str],
    after_tree_sha256: [u8; 32],
    after_file_bytes: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum IndexPolicy {
    Required,
    Forbidden,
}

#[cfg(test)]
const SYNTHETIC_PATCH_SPEC: PatchApplicationSpec = PatchApplicationSpec {
    working_directory: PatchWorkingDirectory::Vendor,
    strip_level: 1,
    index_policy: IndexPolicy::Required,
};

const HISTORICAL_INITIAL_TREE_SHA256: [u8; 32] = [
    0xdf, 0xe4, 0x05, 0x06, 0x07, 0x53, 0xb9, 0x0e, 0xf5, 0x80, 0xb4, 0xa1, 0x05, 0xa5, 0xc0, 0xe9,
    0xcf, 0x4b, 0xb4, 0xf0, 0x6a, 0xdc, 0x79, 0x14, 0x5f, 0x94, 0x57, 0x2f, 0x7a, 0x4c, 0x58, 0x51,
];
const HISTORICAL_P1_TREE_SHA256: [u8; 32] = [
    0x3b, 0x2e, 0x6e, 0x4d, 0x90, 0xd1, 0xdc, 0x1a, 0xe8, 0x5d, 0x07, 0xb9, 0x07, 0xcc, 0x8b, 0x45,
    0x08, 0xf2, 0x96, 0x79, 0x0a, 0xec, 0xc8, 0x8b, 0x5f, 0x66, 0x14, 0x0a, 0xf3, 0x41, 0x69, 0xae,
];
const HISTORICAL_P2_TREE_SHA256: [u8; 32] = [
    0xab, 0x0b, 0x52, 0xcc, 0x2f, 0x07, 0x3f, 0x56, 0x3e, 0xc5, 0x78, 0x78, 0x89, 0x3c, 0xb9, 0x08,
    0x85, 0xfb, 0xbd, 0xba, 0x23, 0x0e, 0x16, 0x54, 0x90, 0x88, 0x25, 0x12, 0xa6, 0x37, 0x4b, 0x7c,
];
const HISTORICAL_P3_TREE_SHA256: [u8; 32] = [
    0xb3, 0xd3, 0xe1, 0x49, 0x84, 0xe4, 0x95, 0xa6, 0x89, 0xf6, 0x87, 0x50, 0xef, 0x37, 0x3a, 0xf6,
    0x25, 0x5e, 0x9e, 0x47, 0x1a, 0xf1, 0x7d, 0xa0, 0x76, 0x86, 0x22, 0x5e, 0x71, 0x6f, 0x27, 0x84,
];
const HISTORICAL_CURATED_TREE_ENTRIES: usize = 81;
const HISTORICAL_CURATED_FILE_COUNT: usize = 68;
const HISTORICAL_CURATED_FILE_BYTES: usize = 2_455_232;
const HISTORICAL_CURATED_TREE_SHA256: [u8; 32] = [
    0x69, 0x87, 0x96, 0xaa, 0xfd, 0x8a, 0x33, 0xb5, 0x48, 0x62, 0x27, 0xe5, 0xea, 0x0e, 0xb7, 0xc4,
    0xe2, 0x4b, 0x38, 0xf3, 0xf8, 0xaf, 0x96, 0x92, 0x14, 0x20, 0xcc, 0x49, 0x18, 0x8b, 0x6a, 0xe9,
];
const HISTORICAL_OFFICIAL_FILES_SHA256: [u8; 32] = [
    0x3e, 0x2c, 0x1f, 0x19, 0x14, 0xe2, 0x15, 0xd8, 0x93, 0x13, 0x77, 0x98, 0x9a, 0x40, 0x82, 0xe6,
    0x22, 0x5f, 0x0c, 0xc1, 0x8c, 0x10, 0xd4, 0x1d, 0x9e, 0x7f, 0x28, 0x1d, 0x49, 0x7a, 0x73, 0xe7,
];
const HISTORICAL_VENDOR_FILES_SHA256: [u8; 32] = [
    0x0b, 0x9a, 0x65, 0x35, 0xf4, 0x00, 0x91, 0x6f, 0x48, 0xef, 0xdc, 0xcb, 0x4b, 0x86, 0x76, 0xd7,
    0xe8, 0xa3, 0x74, 0xc4, 0x86, 0x7c, 0x39, 0x6d, 0xa3, 0x96, 0xe9, 0xb2, 0x32, 0xd2, 0x28, 0xbf,
];
const HISTORICAL_COMMON_OFFICIAL_FILES_SHA256: [u8; 32] = [
    0xd8, 0x61, 0xd3, 0x26, 0x40, 0x02, 0xff, 0xf0, 0xc3, 0xe7, 0x58, 0x95, 0xf0, 0x57, 0xaa, 0x95,
    0xc2, 0x3d, 0x70, 0x22, 0xbd, 0x43, 0x96, 0x1f, 0xcb, 0x0d, 0x90, 0xd1, 0x78, 0xa4, 0xc1, 0x20,
];
const HISTORICAL_COMMON_VENDOR_FILES_SHA256: [u8; 32] = [
    0x31, 0xf7, 0x5e, 0x01, 0x33, 0x1b, 0x7f, 0x51, 0x08, 0x77, 0x23, 0x66, 0x42, 0xe8, 0x0b, 0x30,
    0xf6, 0xee, 0xc5, 0xa6, 0x21, 0xfa, 0xb2, 0x52, 0xb1, 0x6a, 0xf3, 0x6c, 0x3c, 0xa8, 0x06, 0x88,
];
const HISTORICAL_IDENTICAL_FILES_SHA256: [u8; 32] = [
    0x03, 0xd7, 0x3a, 0xe8, 0x47, 0x70, 0xa5, 0x94, 0x12, 0x30, 0x8e, 0x04, 0x90, 0x17, 0x40, 0x8a,
    0x38, 0x2d, 0xe3, 0xa3, 0x48, 0x65, 0xd1, 0x73, 0xbe, 0x94, 0x7d, 0xce, 0x03, 0x2a, 0x92, 0x92,
];
const HISTORICAL_OMITTED_FILES_SHA256: [u8; 32] = [
    0xef, 0x93, 0x30, 0xee, 0x63, 0x6e, 0x5e, 0x5a, 0x17, 0xa0, 0xd2, 0xfb, 0x5e, 0x09, 0xd9, 0x9c,
    0x6d, 0xaa, 0x92, 0x60, 0x41, 0x3f, 0x80, 0x72, 0xc0, 0x71, 0xa1, 0x62, 0x51, 0x0f, 0x0f, 0x93,
];
const HISTORICAL_VENDOR_ONLY_FILES_SHA256: [u8; 32] = [
    0x2b, 0x4a, 0xd4, 0xe0, 0xc2, 0x74, 0x31, 0xca, 0x67, 0xaf, 0xdd, 0xe8, 0x28, 0x9d, 0xab, 0x9c,
    0xcc, 0xba, 0xe5, 0x16, 0x37, 0x30, 0xeb, 0x90, 0x55, 0x77, 0x22, 0x82, 0x62, 0xf3, 0x78, 0xea,
];
const HISTORICAL_CHANGED_COMMON_PATHS: [&str; 4] = [
    "Cargo.toml",
    "src/h3/mod.rs",
    "src/h3/qpack/decoder.rs",
    "src/h3/stream.rs",
];
const HISTORICAL_P1_ALLOWLIST: &[&str] = &[
    "quiche-0.29.3/src/h3/mod.rs",
    "quiche-0.29.3/src/h3/stream.rs",
];
const HISTORICAL_P2_ALLOWLIST: &[&str] = HISTORICAL_P1_ALLOWLIST;
const HISTORICAL_P3_ALLOWLIST: &[&str] = &[
    "quiche-0.29.3/src/h3/mod.rs",
    "quiche-0.29.3/src/h3/qpack/decoder.rs",
    "quiche-0.29.3/src/h3/stream.rs",
];
const HISTORICAL_PATCHES: [HistoricalPatchSpec; 3] = [
    HistoricalPatchSpec {
        application: PatchApplicationSpec {
            working_directory: PatchWorkingDirectory::Vendor,
            strip_level: 1,
            index_policy: IndexPolicy::Required,
        },
        allowlist: HISTORICAL_P1_ALLOWLIST,
        after_tree_sha256: HISTORICAL_P1_TREE_SHA256,
        after_file_bytes: 2_683_090,
    },
    HistoricalPatchSpec {
        application: PatchApplicationSpec {
            working_directory: PatchWorkingDirectory::Vendor,
            strip_level: 1,
            index_policy: IndexPolicy::Forbidden,
        },
        allowlist: HISTORICAL_P2_ALLOWLIST,
        after_tree_sha256: HISTORICAL_P2_TREE_SHA256,
        after_file_bytes: 2_683_399,
    },
    HistoricalPatchSpec {
        application: PatchApplicationSpec {
            working_directory: PatchWorkingDirectory::StagingRoot,
            strip_level: 1,
            index_policy: IndexPolicy::Required,
        },
        allowlist: HISTORICAL_P3_ALLOWLIST,
        after_tree_sha256: HISTORICAL_P3_TREE_SHA256,
        after_file_bytes: 2_685_901,
    },
];

// Synthetic bytes remain test-only. Production accepts only the fixed S3
// historical archive and patch constants above.
#[cfg(test)]
const SYNTHETIC_ARCHIVE_BYTES: u64 = 158;
#[cfg(test)]
const SYNTHETIC_ARCHIVE_SHA256: [u8; 32] = [
    0x29, 0xfc, 0xc1, 0x33, 0x7a, 0x95, 0x12, 0x11, 0xe8, 0xbe, 0xc8, 0x4b, 0x46, 0x76, 0xab, 0x95,
    0xa7, 0xa2, 0xb7, 0x9d, 0xb9, 0x0d, 0xaa, 0x84, 0x91, 0xda, 0xdc, 0x94, 0xba, 0x2d, 0x7f, 0xc2,
];
#[cfg(test)]
const SYNTHETIC_INITIAL_TREE_SHA256: [u8; 32] = [
    0x0f, 0x92, 0xf8, 0x48, 0xf4, 0xf8, 0x5a, 0x4b, 0xab, 0x6a, 0x3f, 0xbd, 0x84, 0x8b, 0xea, 0x3d,
    0xb0, 0xa8, 0xc4, 0x83, 0x7b, 0xda, 0xe3, 0x50, 0x15, 0x44, 0x4b, 0x00, 0xf7, 0x85, 0x1d, 0xc5,
];
#[cfg(test)]
const SYNTHETIC_FINAL_TREE_SHA256: [u8; 32] = [
    0x50, 0xe8, 0xc4, 0x08, 0x41, 0xff, 0xea, 0x26, 0xba, 0x35, 0x44, 0x84, 0x78, 0x04, 0x5c, 0x54,
    0x7d, 0x63, 0x7b, 0x88, 0x6f, 0x05, 0x76, 0x2b, 0x4b, 0x13, 0xc0, 0x25, 0x9d, 0x54, 0xff, 0xf6,
];

const HISTORICAL_ARCHIVE_SHA256: [u8; 32] = [
    0x61, 0x16, 0x6d, 0x27, 0x59, 0x1e, 0xb7, 0xcb, 0x13, 0x10, 0xee, 0xc2, 0xb8, 0xfc, 0x6a, 0xe0,
    0xe0, 0x68, 0x6e, 0x9e, 0x4e, 0xd7, 0x42, 0xa3, 0xff, 0xc6, 0x31, 0x71, 0x71, 0x17, 0x5e, 0x7d,
];
const HISTORICAL_EXPANDED_SHA256: [u8; 32] = [
    0x7a, 0x0e, 0x35, 0x67, 0x01, 0x5f, 0x7a, 0x11, 0x1c, 0x3a, 0xdc, 0x6e, 0x65, 0xa3, 0x36, 0xdb,
    0xf6, 0x34, 0xfe, 0xe1, 0x16, 0x93, 0xe8, 0x3e, 0x44, 0xdf, 0xf2, 0xae, 0xd6, 0xe2, 0x43, 0x9b,
];

#[derive(Clone, Copy)]
struct ArchiveSpec {
    exact_bytes: u64,
    maximum_bytes: u64,
    sha256: [u8; 32],
    exact_expanded_bytes: usize,
    expanded_sha256: [u8; 32],
}

#[cfg(test)]
const SYNTHETIC_SPEC: ArchiveSpec = ArchiveSpec {
    exact_bytes: SYNTHETIC_ARCHIVE_BYTES,
    maximum_bytes: MAX_ARCHIVE_BYTES,
    sha256: SYNTHETIC_ARCHIVE_SHA256,
    exact_expanded_bytes: 3_072,
    expanded_sha256: [
        0x42, 0x73, 0x15, 0x86, 0xd0, 0x25, 0x5f, 0x8f, 0xef, 0x75, 0x1a, 0x68, 0x21, 0xd4, 0xfb,
        0x83, 0x83, 0x18, 0xc8, 0x7d, 0x50, 0xef, 0x1b, 0xdf, 0xac, 0xa5, 0xc4, 0x17, 0x16, 0xf5,
        0x2b, 0xd1,
    ],
};

const HISTORICAL_SPEC: ArchiveSpec = ArchiveSpec {
    exact_bytes: 453_798,
    maximum_bytes: MAX_ARCHIVE_BYTES,
    sha256: HISTORICAL_ARCHIVE_SHA256,
    exact_expanded_bytes: 2_748_928,
    expanded_sha256: HISTORICAL_EXPANDED_SHA256,
};

struct HistoricalGitInputs {
    patches: [Vec<u8>; 3],
    final_vendor_tree: Tree,
}

struct HistoricalAccounting {
    omitted: BTreeSet<String>,
    vendor_only: BTreeSet<String>,
}

fn main() {
    run_signal_process(
        || Ok(env::args_os().collect()),
        verify_historical_replay,
        || true,
    )
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
    verify_archive: impl FnOnce(&Path, &AtomicUsize) -> Result<(), ()>,
    red_cleanup: impl FnOnce() -> bool,
) -> ! {
    install_private_panic_hook();
    let state = Arc::new(AtomicUsize::new(ACTIVE));
    let registrations = SignalRegistrations::install(Arc::clone(&state));
    let replay = catch_unwind(AssertUnwindSafe(|| -> Result<(), ()> {
        let args = prepare_args()?;
        let archive = parse_args(args)?;
        verify_archive(&archive, state.as_ref())?;
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
    verify_synthetic_replay(archive, spec, &AtomicUsize::new(ACTIVE))
}

fn verify_historical_replay(archive: &Path, state: &AtomicUsize) -> Result<(), ()> {
    let input = open_and_hash_archive(archive, HISTORICAL_SPEC)?;
    check_active(state)?;
    let repo = repository_root()?;
    let repo_fd = open(&repo, directory_open_flags(), Mode::empty()).map_err(|_| ())?;
    let repo_identity = stat_identity(&fstat(&repo_fd).map_err(|_| ())?)?;
    let inputs = read_historical_git_chain(&repo)?;
    check_active(state)?;
    let mut mask = UmaskGuard::install();
    let replay = replay_worker(
        input,
        HISTORICAL_SPEC,
        repo_identity,
        |tree, state| replay_historical_tree(tree, &inputs, state),
        state,
    );
    mask.restore();
    replay
}

#[cfg(test)]
fn verify_synthetic_replay(
    archive: &Path,
    spec: ArchiveSpec,
    state: &AtomicUsize,
) -> Result<(), ()> {
    let input = open_and_hash_archive(archive, spec)?;
    check_active(state)?;
    let repo = repository_root()?;
    let repo_fd = open(&repo, directory_open_flags(), Mode::empty()).map_err(|_| ())?;
    let repo_identity = stat_identity(&fstat(&repo_fd).map_err(|_| ())?)?;
    read_synthetic_git_chain(&repo)?;
    check_active(state)?;
    let mut mask = UmaskGuard::install();
    let replay = replay_worker(input, spec, repo_identity, replay_synthetic_tree, state);
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
    replay_tree: impl FnOnce(&mut Tree, &AtomicUsize) -> Result<(), ()>,
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
        if expanded.len() != spec.exact_expanded_bytes
            || <[u8; 32]>::from(Sha256::digest(&expanded)) != spec.expanded_sha256
        {
            return Err(());
        }
        let mut tree = parse_ustar_cancelled(&expanded, state)?;
        replay_tree(&mut tree, state)?;
        check_active(state)?;
        test_after_final_manifest_barrier();
        check_active(state)
    })();
    let cleanup = workspace.cleanup();
    cleanup?;
    replay
}

#[cfg(test)]
fn replay_synthetic_tree(tree: &mut Tree, state: &AtomicUsize) -> Result<(), ()> {
    if tree_manifest_sha256(tree) != SYNTHETIC_INITIAL_TREE_SHA256 {
        return Err(());
    }
    apply_unified_patch_cancelled(
        tree,
        SYNTHETIC_PATCH,
        SYNTHETIC_PATCH_ALLOWLIST,
        SYNTHETIC_PATCH_SPEC,
        state,
    )?;
    test_before_final_manifest_barrier(state)?;
    if tree_manifest_sha256(tree) != SYNTHETIC_FINAL_TREE_SHA256 {
        return Err(());
    }
    Ok(())
}

fn replay_historical_tree(
    tree: &mut Tree,
    inputs: &HistoricalGitInputs,
    state: &AtomicUsize,
) -> Result<(), ()> {
    if tree.len() != 101
        || tree_file_stats(tree)? != (87, 2_680_769)
        || tree_manifest_sha256(tree) != HISTORICAL_INITIAL_TREE_SHA256
    {
        return Err(());
    }
    verify_historical_archive_markers(tree)?;
    let accounting = verify_historical_accounting(tree, &inputs.final_vendor_tree)?;
    for (index, (patch, patch_spec)) in inputs
        .patches
        .iter()
        .zip(HISTORICAL_PATCHES.iter())
        .enumerate()
    {
        apply_unified_patch_cancelled(
            tree,
            patch,
            patch_spec.allowlist,
            patch_spec.application,
            state,
        )?;
        if index == HISTORICAL_PATCHES.len() - 1 {
            test_before_final_manifest_barrier(state)?;
        }
        if tree.len() != 101
            || tree_file_stats(tree)? != (87, patch_spec.after_file_bytes)
            || tree_manifest_sha256(tree) != patch_spec.after_tree_sha256
        {
            return Err(());
        }
    }
    verify_curated_vendor_closure(tree, &inputs.final_vendor_tree, &accounting)
}

fn tree_file_stats(tree: &Tree) -> Result<(usize, usize), ()> {
    let mut count = 0_usize;
    let mut bytes = 0_usize;
    for entry in tree.values() {
        if let TreeEntry::File(file) = entry {
            count = count.checked_add(1).ok_or(())?;
            bytes = bytes.checked_add(file.len()).ok_or(())?;
        }
    }
    Ok((count, bytes))
}

fn verify_historical_archive_markers(tree: &Tree) -> Result<(), ()> {
    const VCS_INFO: &[u8] = b"{\n  \"git\": {\n    \"sha1\": \"09b125d4cfc16e78d73d8382c93926f3aba063d4\"\n  },\n  \"path_in_vcs\": \"quiche\"\n}";
    const COPYING_SHA256: [u8; 32] = [
        0x2e, 0xf4, 0xb5, 0xab, 0xfc, 0xe3, 0x87, 0xa8, 0x39, 0x33, 0xbd, 0xa7, 0x38, 0xe7, 0x24,
        0x67, 0xa7, 0x9d, 0x15, 0xc1, 0xc1, 0x76, 0x79, 0x14, 0x3e, 0xc5, 0x50, 0x11, 0xda, 0xe6,
        0x6b, 0x84,
    ];
    match tree.get("quiche-0.29.3/.cargo_vcs_info.json") {
        Some(TreeEntry::File(bytes)) if bytes == VCS_INFO => {}
        _ => return Err(()),
    }
    match tree.get("quiche-0.29.3/COPYING") {
        Some(TreeEntry::File(bytes))
            if bytes.len() == 1_306
                && <[u8; 32]>::from(Sha256::digest(bytes)) == COPYING_SHA256 => {}
        _ => return Err(()),
    }
    Ok(())
}

// These checks close a complete byte classification. They do not claim that
// curated or support bytes came from the upstream archive, nor do they prove
// the historical reason for retaining or omitting any path.
fn verify_historical_accounting(
    official_tree: &Tree,
    vendor_tree: &Tree,
) -> Result<HistoricalAccounting, ()> {
    let official = relative_file_map(official_tree)?;
    let vendor = relative_file_map(vendor_tree)?;
    let official_paths = official.keys().cloned().collect::<BTreeSet<_>>();
    let vendor_paths = vendor.keys().cloned().collect::<BTreeSet<_>>();
    let common = official_paths
        .intersection(&vendor_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let omitted = official_paths
        .difference(&vendor_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let vendor_only = vendor_paths
        .difference(&official_paths)
        .cloned()
        .collect::<BTreeSet<_>>();
    let identical = common
        .iter()
        .filter(|path| official.get(*path) == vendor.get(*path))
        .cloned()
        .collect::<BTreeSet<_>>();
    let changed = common
        .difference(&identical)
        .cloned()
        .collect::<BTreeSet<_>>();
    let expected_changed = HISTORICAL_CHANGED_COMMON_PATHS
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();

    if file_subset_stats(&official, &official_paths)? != (87, 2_680_769)
        || file_subset_sha256(&official, &official_paths)? != HISTORICAL_OFFICIAL_FILES_SHA256
        || file_subset_stats(&vendor, &vendor_paths)?
            != (HISTORICAL_CURATED_FILE_COUNT, HISTORICAL_CURATED_FILE_BYTES)
        || file_subset_sha256(&vendor, &vendor_paths)? != HISTORICAL_VENDOR_FILES_SHA256
        || file_subset_stats(&official, &common)? != (62, 2_420_911)
        || file_subset_sha256(&official, &common)? != HISTORICAL_COMMON_OFFICIAL_FILES_SHA256
        || file_subset_stats(&vendor, &common)? != (62, 2_423_944)
        || file_subset_sha256(&vendor, &common)? != HISTORICAL_COMMON_VENDOR_FILES_SHA256
        || file_subset_stats(&official, &identical)? != (58, 2_026_634)
        || file_subset_sha256(&official, &identical)? != HISTORICAL_IDENTICAL_FILES_SHA256
        || file_subset_stats(&official, &omitted)? != (25, 259_858)
        || file_subset_sha256(&official, &omitted)? != HISTORICAL_OMITTED_FILES_SHA256
        || file_subset_stats(&vendor, &vendor_only)? != (6, 31_288)
        || file_subset_sha256(&vendor, &vendor_only)? != HISTORICAL_VENDOR_ONLY_FILES_SHA256
        || file_subset_stats(&official, &changed)? != (4, 394_277)
        || file_subset_stats(&vendor, &changed)? != (4, 397_310)
        || changed != expected_changed
        || official.get("Cargo.toml").map(|bytes| bytes.len()) != Some(3_829)
        || vendor.get("Cargo.toml").map(|bytes| bytes.len()) != Some(1_730)
        || 2_680_769_usize
            .checked_add(2_321)
            .and_then(|bytes| bytes.checked_add(309))
            .and_then(|bytes| bytes.checked_add(2_502))
            != Some(2_685_901)
        || 2_685_901_usize
            .checked_sub(259_858)
            .and_then(|bytes| bytes.checked_sub(3_829))
            .and_then(|bytes| bytes.checked_add(1_730))
            .and_then(|bytes| bytes.checked_add(31_288))
            != Some(HISTORICAL_CURATED_FILE_BYTES)
    {
        return Err(());
    }
    Ok(HistoricalAccounting {
        omitted,
        vendor_only,
    })
}

fn relative_file_map(tree: &Tree) -> Result<BTreeMap<String, &[u8]>, ()> {
    const ROOT: &str = "quiche-0.29.3";
    if tree.get(ROOT) != Some(&TreeEntry::Directory) {
        return Err(());
    }
    let prefix = format!("{ROOT}/");
    let mut files = BTreeMap::new();
    for (path, entry) in tree {
        if path == ROOT {
            continue;
        }
        let relative = path.strip_prefix(&prefix).ok_or(())?;
        if relative.is_empty() {
            return Err(());
        }
        if let TreeEntry::File(bytes) = entry {
            files.insert(relative.to_owned(), bytes.as_slice());
        }
    }
    Ok(files)
}

fn file_subset_stats(
    files: &BTreeMap<String, &[u8]>,
    paths: &BTreeSet<String>,
) -> Result<(usize, usize), ()> {
    let mut bytes = 0_usize;
    for path in paths {
        bytes = bytes
            .checked_add(files.get(path).ok_or(())?.len())
            .ok_or(())?;
    }
    Ok((paths.len(), bytes))
}

fn file_subset_sha256(
    files: &BTreeMap<String, &[u8]>,
    paths: &BTreeSet<String>,
) -> Result<[u8; 32], ()> {
    let mut hasher = Sha256::new();
    for path in paths {
        let bytes = files.get(path).ok_or(())?;
        hasher.update(b"F\0");
        hasher.update(path.as_bytes());
        hasher.update(b"\0");
        hasher.update(bytes.len().to_string().as_bytes());
        hasher.update(b"\0");
        hasher.update(Sha256::digest(bytes));
        hasher.update(b"\n");
    }
    Ok(hasher.finalize().into())
}

fn verify_curated_vendor_closure(
    patched_tree: &Tree,
    vendor_tree: &Tree,
    accounting: &HistoricalAccounting,
) -> Result<(), ()> {
    const ROOT: &str = "quiche-0.29.3";
    let vendor_files = relative_file_map(vendor_tree)?;
    for path in &HISTORICAL_CHANGED_COMMON_PATHS[1..] {
        let canonical = format!("{ROOT}/{path}");
        match (patched_tree.get(&canonical), vendor_files.get(*path)) {
            (Some(TreeEntry::File(actual)), Some(expected)) if actual.as_slice() == *expected => {}
            _ => return Err(()),
        }
    }

    let mut curated = patched_tree.clone();
    for relative in &accounting.omitted {
        let canonical = format!("{ROOT}/{relative}");
        if !matches!(curated.remove(&canonical), Some(TreeEntry::File(_))) {
            return Err(());
        }
    }
    let cargo = vendor_files.get("Cargo.toml").ok_or(())?.to_vec();
    if !matches!(
        curated.insert(format!("{ROOT}/Cargo.toml"), TreeEntry::File(cargo)),
        Some(TreeEntry::File(_))
    ) {
        return Err(());
    }
    for relative in &accounting.vendor_only {
        let canonical = format!("{ROOT}/{relative}");
        insert_inferred_directories(&mut curated, &canonical)?;
        let bytes = vendor_files.get(relative).ok_or(())?.to_vec();
        if curated.insert(canonical, TreeEntry::File(bytes)).is_some() {
            return Err(());
        }
    }
    prune_empty_directories(&mut curated)?;
    if curated != *vendor_tree
        || curated.len() != HISTORICAL_CURATED_TREE_ENTRIES
        || tree_file_stats(&curated)?
            != (HISTORICAL_CURATED_FILE_COUNT, HISTORICAL_CURATED_FILE_BYTES)
        || tree_manifest_sha256(&curated) != HISTORICAL_CURATED_TREE_SHA256
    {
        return Err(());
    }
    Ok(())
}

fn prune_empty_directories(tree: &mut Tree) -> Result<(), ()> {
    let mut required = BTreeSet::new();
    for (path, entry) in tree.iter() {
        if !matches!(entry, TreeEntry::File(_)) {
            continue;
        }
        let parts = path.split('/').collect::<Vec<_>>();
        for length in 1..parts.len() {
            required.insert(parts[..length].join("/"));
        }
    }
    tree.retain(|path, entry| matches!(entry, TreeEntry::File(_)) || required.contains(path));
    if tree
        .values()
        .any(|entry| matches!(entry, TreeEntry::Directory))
    {
        Ok(())
    } else {
        Err(())
    }
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

fn read_historical_git_chain(repo: &Path) -> Result<HistoricalGitInputs, ()> {
    let p1_p2_commit = read_fixed_git_object(
        repo,
        "commit",
        HISTORICAL_P1_P2_COMMIT_OID,
        HISTORICAL_P1_P2_COMMIT_BYTES,
        HISTORICAL_P1_P2_COMMIT_SHA256,
    )?;
    require_commit_tree(&p1_p2_commit, HISTORICAL_P1_P2_ROOT_TREE_OID)?;
    let p1_p2_root = read_fixed_git_object(
        repo,
        "tree",
        HISTORICAL_P1_P2_ROOT_TREE_OID,
        HISTORICAL_P1_P2_ROOT_TREE_BYTES,
        HISTORICAL_P1_P2_ROOT_TREE_SHA256,
    )?;
    require_tree_entry(
        &p1_p2_root,
        b"40000 vendor\0",
        HISTORICAL_P1_P2_VENDOR_TREE_OID,
    )?;
    let p1_p2_vendor = read_fixed_git_object(
        repo,
        "tree",
        HISTORICAL_P1_P2_VENDOR_TREE_OID,
        HISTORICAL_P1_P2_VENDOR_TREE_BYTES,
        HISTORICAL_P1_P2_VENDOR_TREE_SHA256,
    )?;
    require_tree_entry(
        &p1_p2_vendor,
        b"40000 quiche-0.29.3\0",
        HISTORICAL_P1_P2_QUICHE_TREE_OID,
    )?;
    let p1_p2_quiche = read_fixed_git_object(
        repo,
        "tree",
        HISTORICAL_P1_P2_QUICHE_TREE_OID,
        HISTORICAL_P1_P2_QUICHE_TREE_BYTES,
        HISTORICAL_P1_P2_QUICHE_TREE_SHA256,
    )?;
    require_tree_entry(
        &p1_p2_quiche,
        b"40000 PATCHES\0",
        HISTORICAL_P1_P2_PATCH_TREE_OID,
    )?;
    let p1_p2_patches = read_fixed_git_object(
        repo,
        "tree",
        HISTORICAL_P1_P2_PATCH_TREE_OID,
        HISTORICAL_P1_P2_PATCH_TREE_BYTES,
        HISTORICAL_P1_P2_PATCH_TREE_SHA256,
    )?;
    require_tree_entry(
        &p1_p2_patches,
        b"100644 quiche-0.29.3-reject-peer-push-activity.patch\0",
        HISTORICAL_P1_BLOB_OID,
    )?;
    require_tree_entry(
        &p1_p2_patches,
        b"100644 maverick-adoption-review-hardening.patch\0",
        HISTORICAL_P2_BLOB_OID,
    )?;

    let p3_commit = read_fixed_git_object(
        repo,
        "commit",
        HISTORICAL_P3_COMMIT_OID,
        HISTORICAL_P3_COMMIT_BYTES,
        HISTORICAL_P3_COMMIT_SHA256,
    )?;
    require_commit_tree(&p3_commit, HISTORICAL_P3_ROOT_TREE_OID)?;
    require_commit_parent(&p3_commit, HISTORICAL_P1_P2_COMMIT_OID)?;
    let p3_root = read_fixed_git_object(
        repo,
        "tree",
        HISTORICAL_P3_ROOT_TREE_OID,
        HISTORICAL_P3_ROOT_TREE_BYTES,
        HISTORICAL_P3_ROOT_TREE_SHA256,
    )?;
    require_tree_entry(
        &p3_root,
        b"40000 vendor\0",
        HISTORICAL_FINAL_VENDOR_TREE_OID,
    )?;
    let final_vendor = read_fixed_git_object(
        repo,
        "tree",
        HISTORICAL_FINAL_VENDOR_TREE_OID,
        HISTORICAL_FINAL_VENDOR_TREE_BYTES,
        HISTORICAL_FINAL_VENDOR_TREE_SHA256,
    )?;
    require_tree_entry(
        &final_vendor,
        b"40000 quiche-0.29.3\0",
        HISTORICAL_FINAL_QUICHE_TREE_OID,
    )?;
    let final_quiche = read_fixed_git_object(
        repo,
        "tree",
        HISTORICAL_FINAL_QUICHE_TREE_OID,
        HISTORICAL_FINAL_QUICHE_TREE_BYTES,
        HISTORICAL_FINAL_QUICHE_TREE_SHA256,
    )?;
    require_tree_entry(
        &final_quiche,
        b"40000 PATCHES\0",
        HISTORICAL_FINAL_PATCH_TREE_OID,
    )?;
    let final_patches = read_fixed_git_object(
        repo,
        "tree",
        HISTORICAL_FINAL_PATCH_TREE_OID,
        HISTORICAL_FINAL_PATCH_TREE_BYTES,
        HISTORICAL_FINAL_PATCH_TREE_SHA256,
    )?;
    require_tree_entry(
        &final_patches,
        b"100644 maverick-h3-trace-privacy.patch\0",
        HISTORICAL_P3_BLOB_OID,
    )?;

    let final_commit = read_fixed_git_object(
        repo,
        "commit",
        HISTORICAL_FINAL_COMMIT_OID,
        HISTORICAL_FINAL_COMMIT_BYTES,
        HISTORICAL_FINAL_COMMIT_SHA256,
    )?;
    require_commit_tree(&final_commit, HISTORICAL_FINAL_ROOT_TREE_OID)?;
    let final_root = read_fixed_git_object(
        repo,
        "tree",
        HISTORICAL_FINAL_ROOT_TREE_OID,
        HISTORICAL_FINAL_ROOT_TREE_BYTES,
        HISTORICAL_FINAL_ROOT_TREE_SHA256,
    )?;
    require_tree_entry(
        &final_root,
        b"40000 vendor\0",
        HISTORICAL_FINAL_VENDOR_TREE_OID,
    )?;

    let p1 = read_fixed_git_object(
        repo,
        "blob",
        HISTORICAL_P1_BLOB_OID,
        HISTORICAL_P1_BLOB_BYTES,
        HISTORICAL_P1_BLOB_SHA256,
    )?;
    let p2 = read_fixed_git_object(
        repo,
        "blob",
        HISTORICAL_P2_BLOB_OID,
        HISTORICAL_P2_BLOB_BYTES,
        HISTORICAL_P2_BLOB_SHA256,
    )?;
    let p3 = read_fixed_git_object(
        repo,
        "blob",
        HISTORICAL_P3_BLOB_OID,
        HISTORICAL_P3_BLOB_BYTES,
        HISTORICAL_P3_BLOB_SHA256,
    )?;
    let final_vendor_tree = read_final_vendor_tree(repo, &final_quiche)?;
    Ok(HistoricalGitInputs {
        patches: [p1, p2, p3],
        final_vendor_tree,
    })
}

fn read_final_vendor_tree(repo: &Path, root_object: &[u8]) -> Result<Tree, ()> {
    const PACKAGE_ROOT: &str = "quiche-0.29.3";

    let mut tree = Tree::new();
    tree.insert(PACKAGE_ROOT.to_owned(), TreeEntry::Directory);
    let mut seen_trees = BTreeSet::from([HISTORICAL_FINAL_QUICHE_TREE_OID.to_owned()]);
    insert_bound_git_tree(
        repo,
        root_object,
        PACKAGE_ROOT,
        0,
        &mut seen_trees,
        &mut tree,
    )?;
    if tree.len() != HISTORICAL_CURATED_TREE_ENTRIES
        || tree_file_stats(&tree)? != (HISTORICAL_CURATED_FILE_COUNT, HISTORICAL_CURATED_FILE_BYTES)
        || tree_manifest_sha256(&tree) != HISTORICAL_CURATED_TREE_SHA256
    {
        return Err(());
    }
    Ok(tree)
}

fn insert_bound_git_tree(
    repo: &Path,
    raw_tree: &[u8],
    parent: &str,
    depth: usize,
    seen_trees: &mut BTreeSet<String>,
    tree: &mut Tree,
) -> Result<(), ()> {
    if raw_tree.is_empty() || depth >= MAX_GIT_TREE_DEPTH {
        return Err(());
    }
    let mut cursor = 0_usize;
    let mut names = BTreeSet::new();
    while cursor < raw_tree.len() {
        let mode_end = raw_tree[cursor..]
            .iter()
            .position(|byte| *byte == b' ')
            .map(|offset| cursor + offset)
            .ok_or(())?;
        let mode = &raw_tree[cursor..mode_end];
        let name_start = mode_end.checked_add(1).ok_or(())?;
        let name_end = raw_tree[name_start..]
            .iter()
            .position(|byte| *byte == 0)
            .map(|offset| name_start + offset)
            .ok_or(())?;
        let name_bytes = &raw_tree[name_start..name_end];
        if name_bytes.is_empty()
            || name_bytes.contains(&b'/')
            || name_bytes.contains(&b'\\')
            || !name_bytes.iter().all(|byte| byte.is_ascii_graphic())
        {
            return Err(());
        }
        let name = std::str::from_utf8(name_bytes).map_err(|_| ())?;
        if name == "." || name == ".." || !names.insert(name.to_owned()) {
            return Err(());
        }
        let oid_start = name_end.checked_add(1).ok_or(())?;
        let oid_end = oid_start.checked_add(20).ok_or(())?;
        let oid = encode_oid_hex(raw_tree.get(oid_start..oid_end).ok_or(())?);
        cursor = oid_end;

        let path = validate_portable_path(format!("{parent}/{name}").as_bytes())?;
        match mode {
            b"40000" => {
                if !seen_trees.insert(oid.clone())
                    || tree.insert(path.clone(), TreeEntry::Directory).is_some()
                    || tree.len() > MAX_TREE_ENTRIES
                {
                    return Err(());
                }
                let child = read_bound_git_object(repo, "tree", &oid, MAX_GIT_TREE_OBJECT_BYTES)?;
                insert_bound_git_tree(repo, &child, &path, depth + 1, seen_trees, tree)?;
            }
            b"100644" => {
                let blob = read_bound_git_object(repo, "blob", &oid, MAX_FILE_BYTES)?;
                if tree.insert(path, TreeEntry::File(blob)).is_some()
                    || tree.len() > MAX_TREE_ENTRIES
                {
                    return Err(());
                }
            }
            _ => return Err(()),
        }
    }
    Ok(())
}

fn encode_oid_hex(oid: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(oid.len() * 2);
    for byte in oid {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn require_commit_tree(commit: &[u8], expected_tree_oid: &str) -> Result<(), ()> {
    if commit.starts_with(format!("tree {expected_tree_oid}\n").as_bytes()) {
        Ok(())
    } else {
        Err(())
    }
}

fn require_commit_parent(commit: &[u8], expected_parent_oid: &str) -> Result<(), ()> {
    let expected = format!("parent {expected_parent_oid}\n");
    if commit
        .windows(expected.len())
        .filter(|window| *window == expected.as_bytes())
        .count()
        == 1
    {
        Ok(())
    } else {
        Err(())
    }
}

fn require_tree_entry(tree: &[u8], prefix: &[u8], oid: &str) -> Result<(), ()> {
    let mut expected = prefix.to_vec();
    expected.extend_from_slice(&decode_oid_hex(oid)?);
    if tree
        .windows(expected.len())
        .filter(|window| *window == expected)
        .count()
        == 1
    {
        Ok(())
    } else {
        Err(())
    }
}

#[cfg(test)]
fn read_synthetic_git_chain(repo: &Path) -> Result<(), ()> {
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
    let bytes = read_bound_git_object(repo, kind, oid, exact_bytes)?;
    if bytes.len() != exact_bytes || <[u8; 32]>::from(Sha256::digest(&bytes)) != sha256 {
        return Err(());
    }
    Ok(bytes)
}

fn read_bound_git_object(
    repo: &Path,
    kind: &str,
    oid: &str,
    maximum_bytes: usize,
) -> Result<Vec<u8>, ()> {
    if !matches!(kind, "blob" | "tree" | "commit") || decode_oid_hex(oid).is_err() {
        return Err(());
    }
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
    let mut bytes = Vec::with_capacity(maximum_bytes.saturating_add(1));
    stdout
        .by_ref()
        .take(u64::try_from(maximum_bytes.saturating_add(1)).map_err(|_| ())?)
        .read_to_end(&mut bytes)
        .map_err(|_| ())?;
    if bytes.len() > maximum_bytes {
        let _ = child.kill();
        let _ = child.wait();
        return Err(());
    }
    let status = child.wait().map_err(|_| ())?;
    if !status.success() {
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
        for field in [&header[100..108], &header[136..148]] {
            parse_octal(field)?;
        }
        for field in [
            &header[108..116],
            &header[116..124],
            &header[329..337],
            &header[337..345],
        ] {
            parse_zero_metadata(field)?;
        }
        if header[157..257].iter().any(|byte| *byte != 0)
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

fn parse_zero_metadata(field: &[u8]) -> Result<(), ()> {
    if field.iter().all(|byte| *byte == 0) || parse_octal(field)? == 0 {
        Ok(())
    } else {
        Err(())
    }
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
    apply_unified_patch_with_spec(tree, patch, allowlist, SYNTHETIC_PATCH_SPEC)
}

#[cfg(test)]
fn apply_unified_patch_with_spec(
    tree: &mut Tree,
    patch: &[u8],
    allowlist: &[&str],
    spec: PatchApplicationSpec,
) -> Result<(), ()> {
    apply_unified_patch_cancelled(tree, patch, allowlist, spec, &AtomicUsize::new(ACTIVE))
}

fn apply_unified_patch_cancelled(
    tree: &mut Tree,
    patch: &[u8],
    allowlist: &[&str],
    spec: PatchApplicationSpec,
    state: &AtomicUsize,
) -> Result<(), ()> {
    if spec.strip_level != 1 {
        return Err(());
    }
    if patch.is_empty() || !patch.ends_with(b"\n") {
        return Err(());
    }
    let text = std::str::from_utf8(patch).map_err(|_| ())?;
    let lines = text.split_inclusive('\n').collect::<Vec<_>>();
    let body_end = if lines.len() > 1 && lines.last().copied() == Some("\n") {
        lines.len() - 1
    } else {
        lines.len()
    };
    let allowed = allowlist
        .iter()
        .map(|path| (*path).to_owned())
        .collect::<BTreeSet<_>>();
    let mut touched = BTreeSet::new();
    let mut index = 0_usize;

    while index < lines.len() {
        check_active(state)?;
        if index > 0 && index + 1 == lines.len() && lines[index] == "\n" {
            index += 1;
            break;
        }
        let diff = lines.get(index).ok_or(())?.strip_suffix('\n').ok_or(())?;
        let rest = diff.strip_prefix("diff --git a/").ok_or(())?;
        let (raw_left, raw_right) = rest.split_once(" b/").ok_or(())?;
        let left = normalize_patch_path(raw_left, spec)?;
        let right = normalize_patch_path(raw_right, spec)?;
        if left != right || !allowed.contains(left) || !touched.insert(left.to_owned()) {
            return Err(());
        }
        index += 1;
        let index_line = lines.get(index).ok_or(())?.strip_suffix('\n').ok_or(())?;
        match spec.index_policy {
            IndexPolicy::Required if valid_index_line(index_line) => index += 1,
            IndexPolicy::Forbidden if index_line.starts_with("--- a/") => {}
            _ => return Err(()),
        }
        if lines.get(index).copied() != Some(format!("--- a/{raw_left}\n").as_str()) {
            return Err(());
        }
        index += 1;
        if lines.get(index).copied() != Some(format!("+++ b/{raw_right}\n").as_str()) {
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
            while index < body_end
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
    if index == lines.len() && touched == allowed {
        Ok(())
    } else {
        Err(())
    }
}

fn normalize_patch_path(path: &str, spec: PatchApplicationSpec) -> Result<&str, ()> {
    match spec.working_directory {
        PatchWorkingDirectory::Vendor => Ok(path),
        PatchWorkingDirectory::StagingRoot => path.strip_prefix("vendor/").ok_or(()),
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
    let line = line.strip_prefix("@@ -").ok_or(())?;
    let (body, context) = line.split_once(" @@").ok_or(())?;
    if !context.is_empty()
        && (!context.starts_with(' ')
            || context[1..].is_empty()
            || !context[1..]
                .bytes()
                .all(|byte| byte == b' ' || byte.is_ascii_graphic()))
    {
        return Err(());
    }
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
            |archive, state| verify_synthetic_replay(archive, SYNTHETIC_SPEC, state),
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
        assert_eq!(synthetic_tar().len(), SYNTHETIC_SPEC.exact_expanded_bytes);
        assert_eq!(
            <[u8; 32]>::from(Sha256::digest(synthetic_tar())),
            SYNTHETIC_SPEC.expanded_sha256
        );
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
            ..SYNTHETIC_SPEC
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
            ..SYNTHETIC_SPEC
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
            ..SYNTHETIC_SPEC
        };

        let swapped = directory.path().join("swapped.crate");
        std::fs::write(&swapped, &archive).unwrap();
        let input = open_and_hash_archive(&swapped, spec).unwrap();
        std::fs::rename(&swapped, directory.path().join("original.crate")).unwrap();
        std::fs::write(&swapped, vec![0_u8; archive.len()]).unwrap();
        let mut mask = UmaskGuard::install();
        assert!(replay_worker(
            input,
            spec,
            test_repo_identity(),
            replay_synthetic_tree,
            &AtomicUsize::new(ACTIVE)
        )
        .is_ok());
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
        assert!(replay_worker(
            input,
            spec,
            test_repo_identity(),
            replay_synthetic_tree,
            &AtomicUsize::new(ACTIVE)
        )
        .is_err());
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
        let many_tree_entries = (0..51)
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
    fn patch_accepts_exactly_one_terminal_bare_blank_line() {
        let _lock = test_lock();
        let mut tree = parse_ustar(&synthetic_tar()).unwrap();
        let mut patch = SYNTHETIC_PATCH.to_vec();
        patch.push(b'\n');

        apply_unified_patch(&mut tree, &patch, SYNTHETIC_PATCH_ALLOWLIST).unwrap();
        assert_eq!(
            tree.get("synthetic-0.0.0/src/message.txt"),
            Some(&TreeEntry::File(b"after\n".to_vec()))
        );
    }

    #[test]
    fn patch_rejects_two_terminal_bare_blank_lines() {
        let _lock = test_lock();
        let mut tree = parse_ustar(&synthetic_tar()).unwrap();
        let mut patch = SYNTHETIC_PATCH.to_vec();
        patch.extend_from_slice(b"\n\n");

        assert!(apply_unified_patch(&mut tree, &patch, SYNTHETIC_PATCH_ALLOWLIST).is_err());
    }

    #[test]
    fn patch_rejects_bare_blank_between_file_header_and_hunk() {
        let _lock = test_lock();
        let mut tree = parse_ustar(&synthetic_tar()).unwrap();
        let patch = String::from_utf8(SYNTHETIC_PATCH.to_vec())
            .unwrap()
            .replace(
                "+++ b/synthetic-0.0.0/src/message.txt\n",
                "+++ b/synthetic-0.0.0/src/message.txt\n\n",
            );

        assert!(
            apply_unified_patch(&mut tree, patch.as_bytes(), SYNTHETIC_PATCH_ALLOWLIST).is_err()
        );
    }

    #[test]
    fn historical_archive_requires_real_archive_bounds() {
        const _: () = assert!(453_798 <= MAX_ARCHIVE_BYTES);
        const _: () = assert!(2_748_928 <= MAX_EXPANDED_BYTES);
        const _: () = assert!(87 <= MAX_TAR_ENTRIES);
        // 87 explicit file headers plus 14 inferred directories, including
        // the inferred quiche-0.29.3 root. There is no explicit directory header.
        const _: () = assert!(101 <= MAX_TREE_ENTRIES);
        const _: () = assert!(417_981 <= MAX_FILE_BYTES);

        assert_eq!(HISTORICAL_SPEC.exact_bytes, 453_798);
        assert_eq!(HISTORICAL_SPEC.maximum_bytes, MAX_ARCHIVE_BYTES);
        assert_eq!(HISTORICAL_SPEC.exact_expanded_bytes, 2_748_928);
    }

    #[test]
    fn historical_ustar_zero_metadata_fields_are_accepted_narrowly() {
        let _lock = test_lock();
        let mut tar = tar_from_entries(&[("quiche-0.29.3/COPYING", b"license", b'0')]);
        tar[108..124].fill(0);
        tar[329..337].copy_from_slice(b"0000000\0");
        tar[337..345].copy_from_slice(b"0000000\0");
        refresh_checksum(&mut tar[..512]);

        assert!(parse_ustar(&tar).is_ok());

        let mut nonzero_device = tar;
        nonzero_device[329..337].copy_from_slice(b"0000001\0");
        refresh_checksum(&mut nonzero_device[..512]);
        assert!(parse_ustar(&nonzero_device).is_err());
    }

    #[test]
    fn historical_hunk_function_context_is_accepted_but_malformed_context_is_not() {
        let _lock = test_lock();
        let mut tree = parse_ustar(&synthetic_tar()).unwrap();
        let context_patch = String::from_utf8(SYNTHETIC_PATCH.to_vec())
            .unwrap()
            .replace("@@ -1 +1 @@", "@@ -1 +1 @@ fn historical_context() {");
        apply_unified_patch(
            &mut tree,
            context_patch.as_bytes(),
            SYNTHETIC_PATCH_ALLOWLIST,
        )
        .unwrap();

        let mut malformed_tree = parse_ustar(&synthetic_tar()).unwrap();
        let malformed = context_patch.replace(
            "@@ -1 +1 @@ fn historical_context() {",
            "@@ -1 +1 @@\tbad-context",
        );
        assert!(apply_unified_patch(
            &mut malformed_tree,
            malformed.as_bytes(),
            SYNTHETIC_PATCH_ALLOWLIST,
        )
        .is_err());
    }

    #[test]
    fn historical_p2_is_the_only_shape_that_may_omit_an_index_line() {
        let _lock = test_lock();
        let mut tree = parse_ustar(&synthetic_tar()).unwrap();
        let p2 = String::from_utf8(SYNTHETIC_PATCH.to_vec())
            .unwrap()
            .replace("index 1111111..2222222 100644\n", "");
        let p2_spec = PatchApplicationSpec {
            index_policy: IndexPolicy::Forbidden,
            ..SYNTHETIC_PATCH_SPEC
        };
        apply_unified_patch_with_spec(&mut tree, p2.as_bytes(), SYNTHETIC_PATCH_ALLOWLIST, p2_spec)
            .unwrap();

        let mut p1_tree = parse_ustar(&synthetic_tar()).unwrap();
        assert!(apply_unified_patch_with_spec(
            &mut p1_tree,
            p2.as_bytes(),
            SYNTHETIC_PATCH_ALLOWLIST,
            SYNTHETIC_PATCH_SPEC,
        )
        .is_err());

        let mut forbidden_index = parse_ustar(&synthetic_tar()).unwrap();
        assert!(apply_unified_patch_with_spec(
            &mut forbidden_index,
            SYNTHETIC_PATCH,
            SYNTHETIC_PATCH_ALLOWLIST,
            p2_spec,
        )
        .is_err());
    }

    #[test]
    fn historical_p3_root_working_directory_maps_to_the_same_upstream_tree() {
        let _lock = test_lock();
        let mut tree = parse_ustar(&synthetic_tar()).unwrap();
        let p3 = String::from_utf8(SYNTHETIC_PATCH.to_vec())
            .unwrap()
            .replace(
                "synthetic-0.0.0/src/message.txt",
                "vendor/synthetic-0.0.0/src/message.txt",
            );
        let p3_spec = PatchApplicationSpec {
            working_directory: PatchWorkingDirectory::StagingRoot,
            ..SYNTHETIC_PATCH_SPEC
        };
        apply_unified_patch_with_spec(&mut tree, p3.as_bytes(), SYNTHETIC_PATCH_ALLOWLIST, p3_spec)
            .unwrap();

        let mut wrong_cwd = parse_ustar(&synthetic_tar()).unwrap();
        assert!(apply_unified_patch_with_spec(
            &mut wrong_cwd,
            p3.as_bytes(),
            SYNTHETIC_PATCH_ALLOWLIST,
            SYNTHETIC_PATCH_SPEC,
        )
        .is_err());
    }

    #[test]
    fn historical_patch_touched_paths_must_equal_the_allowlist() {
        let _lock = test_lock();
        let mut tree = parse_ustar(&synthetic_tar()).unwrap();
        assert!(apply_unified_patch(
            &mut tree,
            SYNTHETIC_PATCH,
            &["synthetic-0.0.0/src/message.txt", "synthetic-0.0.0/LICENSE"]
        )
        .is_err());
    }

    #[test]
    fn accounting_rows_hash_each_file_once_in_relative_path_order() {
        let files = BTreeMap::from([
            ("b".to_owned(), b"yz".as_slice()),
            ("a".to_owned(), b"x".as_slice()),
        ]);
        let paths = BTreeSet::from(["b".to_owned(), "a".to_owned()]);
        assert_eq!(
            file_subset_sha256(&files, &paths).unwrap(),
            [
                0xe5, 0x58, 0x93, 0x70, 0xbc, 0x4f, 0x7d, 0xc1, 0xef, 0x1c, 0x09, 0x01, 0x21, 0x5f,
                0xbb, 0x13, 0x98, 0x93, 0xad, 0x11, 0x3b, 0xa2, 0x45, 0x44, 0x8d, 0x2e, 0x45, 0xac,
                0x45, 0x92, 0x22, 0xb4,
            ]
        );
    }

    #[test]
    fn exact_three_patch_sequence_checks_each_synthetic_stage_manifest() {
        let mut tree = Tree::from([
            ("pkg".to_owned(), TreeEntry::Directory),
            ("pkg/file".to_owned(), TreeEntry::File(b"before\n".to_vec())),
        ]);
        let patches = [
            b"diff --git a/pkg/file b/pkg/file\nindex 1111111..2222222 100644\n--- a/pkg/file\n+++ b/pkg/file\n@@ -1 +1 @@\n-before\n+one\n".as_slice(),
            b"diff --git a/pkg/file b/pkg/file\n--- a/pkg/file\n+++ b/pkg/file\n@@ -1 +1 @@\n-one\n+two\n".as_slice(),
            b"diff --git a/vendor/pkg/file b/vendor/pkg/file\nindex 3333333..4444444 100644\n--- a/vendor/pkg/file\n+++ b/vendor/pkg/file\n@@ -1 +1 @@\n-two\n+three\n".as_slice(),
        ];
        let specs = [
            PatchApplicationSpec {
                working_directory: PatchWorkingDirectory::Vendor,
                strip_level: 1,
                index_policy: IndexPolicy::Required,
            },
            PatchApplicationSpec {
                working_directory: PatchWorkingDirectory::Vendor,
                strip_level: 1,
                index_policy: IndexPolicy::Forbidden,
            },
            PatchApplicationSpec {
                working_directory: PatchWorkingDirectory::StagingRoot,
                strip_level: 1,
                index_policy: IndexPolicy::Required,
            },
        ];
        let expected = [
            "179b112a350a17adadc5843697ae7432a9979fc9cf810792c97dd244c0e1d28c",
            "243a4cd8a939a22d6a11cfdb73a3302696f93faa9deb820190145d77ea669fb4",
            "483c04cc8836367798f6d484f754388f62de4f2ac251f89e5edb0e1bda24a05c",
        ];
        for ((patch, spec), expected_manifest) in patches.into_iter().zip(specs).zip(expected) {
            apply_unified_patch_with_spec(&mut tree, patch, &["pkg/file"], spec).unwrap();
            assert_eq!(
                encode_oid_hex(&tree_manifest_sha256(&tree)),
                expected_manifest
            );
        }
    }

    #[test]
    fn fd_anchored_workspace_copies_and_cleans_the_exact_private_archive() {
        let _lock = test_lock();
        let archive = gzip(&synthetic_tar());
        let spec = ArchiveSpec {
            exact_bytes: archive.len() as u64,
            maximum_bytes: MAX_ARCHIVE_BYTES,
            sha256: Sha256::digest(&archive).into(),
            ..SYNTHETIC_SPEC
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
            ..SYNTHETIC_SPEC
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
            replay_synthetic_tree,
            &AtomicUsize::new(ACTIVE)
        )
        .is_ok());
        mask.restore();
    }

    #[test]
    fn fixed_git_commit_tree_blob_chain_is_read_as_exact_raw_bytes() {
        let _lock = test_lock();
        read_synthetic_git_chain(&repository_root().unwrap()).unwrap();
    }

    #[test]
    fn historical_patch_introduction_chains_bind_all_three_exact_blobs() {
        let _lock = test_lock();
        let inputs = read_historical_git_chain(&repository_root().unwrap()).unwrap();
        let [p1, p2, p3] = inputs.patches;
        assert_eq!(p1.len(), HISTORICAL_P1_BLOB_BYTES);
        assert_eq!(p2.len(), HISTORICAL_P2_BLOB_BYTES);
        assert_eq!(p3.len(), HISTORICAL_P3_BLOB_BYTES);
        assert_eq!(
            inputs.final_vendor_tree.len(),
            HISTORICAL_CURATED_TREE_ENTRIES
        );
        assert_eq!(
            tree_file_stats(&inputs.final_vendor_tree).unwrap(),
            (HISTORICAL_CURATED_FILE_COUNT, HISTORICAL_CURATED_FILE_BYTES)
        );
        assert_eq!(
            tree_manifest_sha256(&inputs.final_vendor_tree),
            HISTORICAL_CURATED_TREE_SHA256
        );
    }

    #[test]
    fn prebuilt_historical_binary_silently_rejects_synthetic_and_invalid_inputs() {
        let _lock = test_lock();
        let binary = production_binary();
        assert!(binary.is_file());
        let fixture = synthetic_fixture();
        let synthetic_red = Command::new(&binary)
            .arg(fixture.path())
            .current_dir(repository_root().unwrap())
            .env_clear()
            .output()
            .unwrap();
        assert!(!synthetic_red.status.success());
        assert!(synthetic_red.stdout.is_empty());
        assert!(synthetic_red.stderr.is_empty());
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
            |_, _| Err(()),
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
