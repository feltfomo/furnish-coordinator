// five test modules each grew their own way of naming a throwaway directory.
// two of them keyed off the nanosecond clock, which two tests entering the same
// nanosecond would have collided on, and only one canonicalized, so the others
// compared paths against a /tmp that is a symlink on some hosts. one counter
// for the whole binary cannot collide, and canonicalizing once means every
// suite compares the path the kernel will report back.

use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

pub(crate) fn scratch_directory(label: &str) -> PathBuf {
    let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let base = std::fs::canonicalize(std::env::temp_dir()).expect("canonicalize temp dir");
    let path = base.join(format!("furnish-{label}-{}-{sequence}", std::process::id()));
    std::fs::create_dir(&path).expect("create scratch directory");
    path
}
