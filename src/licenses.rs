//! `zecd licenses` - print the third-party license notices to stdout.
//!
//! zecd links every dependency statically, so those crates' license texts travel inside the
//! binary and most of them require the text and copyright notice to be reproduced when they
//! do. The packaging ships `THIRD-PARTY-LICENSES.txt` alongside the binary (the release
//! tarball, `/usr/share/doc/zecd/` in the `.deb` and both container images), but the runtime
//! images are `FROM scratch` - no shell, no `cat` - so inside a container the file is only
//! reachable with `docker cp` from a created container. Embedding the same text and printing
//! it makes the notices readable wherever the binary runs (`docker run zecd licenses`), which
//! is the one place a user always has.
//!
//! Deliberately flagless, unlike `example-config`'s `-o FILE`/`--force`: that command's
//! natural target is `<datadir>/zecd.toml`, where refusing to clobber a live deployment's
//! settings is the point. Here there is nothing to protect - a shell redirect is the whole
//! feature - so there is no file-writing path to get wrong.

/// The shipped `THIRD-PARTY-LICENSES.txt`, embedded at compile time.
///
/// Embedding the committed bundle - rather than regenerating at build time - is what keeps the
/// binary's output identical to the file shipped beside it in the `.deb`/tarball/image by
/// construction, and keeps the reproducible StageX/Alpine builds free of cargo-about and its
/// network. It costs ~290 KiB in a multi-megabyte static binary. CI's `licenses` job is what
/// keeps the bundle itself current with the dependency tree; see `scripts/generate-licenses.sh`.
pub const THIRD_PARTY_LICENSES: &str = include_str!("../THIRD-PARTY-LICENSES.txt");

/// Print the third-party license notices to stdout.
#[cfg(feature = "cli")]
pub fn run() -> anyhow::Result<()> {
    crate::example_config::write_stdout(THIRD_PARTY_LICENSES)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The embedded text must be the generated bundle, header and all - the guard against
    /// someone pointing `include_str!` at a placeholder, or the file being emptied.
    #[test]
    fn embedded_text_is_the_generated_bundle() {
        assert!(
            THIRD_PARTY_LICENSES.starts_with("zecd - Third-party licenses"),
            "the bundle keeps about.hbs's header"
        );
        assert!(
            THIRD_PARTY_LICENSES.contains("statically linked"),
            "the header explains why the notices ship with the binary"
        );
    }

    /// Every crate in the tree is listed under some license heading as `  - <name> <version>`.
    /// A bundle that lost its crate list would still start with the header above, so assert
    /// the listing exists and covers a dependency zecd unambiguously links.
    #[test]
    fn embedded_text_lists_the_crates_it_covers() {
        let listed = THIRD_PARTY_LICENSES
            .lines()
            .filter(|l| l.starts_with("  - "))
            .count();
        assert!(
            listed > 100,
            "the bundle lists the crates it covers (found {listed})"
        );
        for crate_name in ["orchard ", "zcash_client_backend ", "tokio "] {
            assert!(
                THIRD_PARTY_LICENSES
                    .lines()
                    .any(|l| l.starts_with(&format!("  - {crate_name}"))),
                "the bundle covers {crate_name}"
            );
        }
    }

    /// Full license texts, not just a manifest of crate names - reproducing the text is the
    /// obligation this file exists to meet.
    #[test]
    fn embedded_text_carries_the_license_texts() {
        assert!(
            THIRD_PARTY_LICENSES.contains("Permission is hereby granted, free of charge"),
            "MIT text is reproduced"
        );
        assert!(
            THIRD_PARTY_LICENSES.contains("Apache License"),
            "Apache-2.0 text is reproduced"
        );
    }
}
