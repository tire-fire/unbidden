//! Scaffolding for tests that need a directory tree.
//!
//! A tree is removed when it goes out of scope, so an assertion that fails
//! halfway does not leave it behind, and two trees made with the same tag never
//! share a directory, however the tests are scheduled.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT: AtomicUsize = AtomicUsize::new(0);

/// A fresh, empty directory under the system temp directory.
#[derive(Debug)]
pub struct Tree(PathBuf);

impl Tree {
    /// `tag` says what the tree is for, and shows in its name.
    pub fn new(tag: &str) -> Tree {
        let unique = NEXT.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("unbidden-{tag}-{}-{unique}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("the temp directory is writable");
        Tree(path)
    }
}

impl Deref for Tree {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.0
    }
}

impl AsRef<Path> for Tree {
    fn as_ref(&self) -> &Path {
        &self.0
    }
}

impl Drop for Tree {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tree_is_its_own_directory_and_goes_when_dropped() {
        let (a, b) = (Tree::new("same"), Tree::new("same"));
        assert_ne!(*a, *b, "one tag, two directories");
        std::fs::write(a.join("f"), b"x").unwrap();
        let path = a.to_path_buf();
        drop(a);
        assert!(!path.exists());
        assert!(b.exists());
    }
}
