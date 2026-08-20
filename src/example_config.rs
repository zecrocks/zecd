//! `zecd example-config` - emit the annotated example configuration file.
//!
//! The analog of `zebrad generate -o` / `zallet example-config -o`: a way to get a valid,
//! documented starting config out of the binary itself, so an operator never has to hunt for
//! `zecd.example.toml` in a source tree they may not have (release tarball, `.deb`, container).

#[cfg(feature = "cli")]
use std::io::Write;
#[cfg(feature = "cli")]
use std::path::Path;

#[cfg(feature = "cli")]
use crate::config::ExampleConfigArgs;

/// The shipped `zecd.example.toml`, embedded at compile time.
///
/// Embedding the real file - rather than serializing a `ConfigFile::default()` - is deliberate:
/// a serde round-trip silently drops every comment, and the comments *are* the value here (the
/// file is ~330 lines, most of them explanation). It also makes the binary's output identical
/// to the file shipped alongside it in the `.deb`/tarball by construction, so the two can never
/// drift. `config::tests::shipped_configs_parse` asserts this exact text deserializes into
/// `ConfigFile`, so `deny_unknown_fields` turns any schema drift into a failing test rather
/// than a config zecd would emit but refuse to load.
pub const EXAMPLE_CONFIG: &str = include_str!("../zecd.example.toml");

/// Print the example config to stdout, or write it to `--output-file`.
#[cfg(feature = "cli")]
pub fn run(args: &ExampleConfigArgs) -> anyhow::Result<()> {
    let Some(path) = output_path(args) else {
        return write_stdout(EXAMPLE_CONFIG);
    };

    write_file(path, args.force, EXAMPLE_CONFIG)?;
    // The confirmation goes to stderr so stdout carries only config text in every mode -
    // `zecd example-config -o - > zecd.toml` and `... -o zecd.toml` produce the same file.
    eprintln!("wrote example config to {}", path.display());
    Ok(())
}

/// The file to write to, or `None` for stdout.
///
/// `-` is the conventional spelling for "stdout" where a path is expected, so it is *not*
/// treated as a file literally named `-`.
#[cfg(feature = "cli")]
fn output_path(args: &ExampleConfigArgs) -> Option<&Path> {
    match args.output_file.as_deref() {
        Some(p) if p != Path::new("-") => Some(p),
        _ => None,
    }
}

/// Write the config to stdout via the locked handle.
///
/// Not `print!`: the payload is ~12 KiB, so `zecd example-config | head` closes the pipe
/// mid-write, and the `println!`/`print!` macros *panic* on `EPIPE` rather than returning it.
/// A broken pipe here means the reader stopped caring, which is a clean exit, not an error.
#[cfg(feature = "cli")]
fn write_stdout(text: &str) -> anyhow::Result<()> {
    let mut out = std::io::stdout().lock();
    match out.write_all(text.as_bytes()).and_then(|()| out.flush()) {
        Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
        other => Ok(other?),
    }
}

/// Write the config to `path`, refusing to clobber an existing file unless `force`.
///
/// The refusal is the point: this command's natural target is `<datadir>/zecd.toml`, where a
/// silent overwrite would discard a live deployment's settings (credentials included).
#[cfg(feature = "cli")]
fn write_file(path: &Path, force: bool, text: &str) -> anyhow::Result<()> {
    let mut f = if force {
        std::fs::File::create(path)
    } else {
        std::fs::File::create_new(path)
    }
    .map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => anyhow::anyhow!(
            "{} already exists; pass --force to overwrite it",
            path.display()
        ),
        _ => anyhow::Error::new(e).context(format!("could not create {}", path.display())),
    })?;
    f.write_all(text.as_bytes())
        .and_then(|()| f.flush())
        .map_err(|e| anyhow::Error::new(e).context(format!("could not write {}", path.display())))
}

#[cfg(all(test, feature = "cli"))]
mod tests {
    use super::*;

    fn args(output_file: Option<&str>, force: bool) -> ExampleConfigArgs {
        ExampleConfigArgs {
            output_file: output_file.map(Into::into),
            force,
        }
    }

    /// The emitted text must stay the *annotated* example - this is what a serialized-defaults
    /// implementation would silently lose. (That it parses as a `ConfigFile` is asserted in
    /// `config::tests::shipped_configs_parse`, where that private type is visible.)
    #[test]
    fn emitted_config_is_the_annotated_example() {
        assert!(
            EXAMPLE_CONFIG.starts_with("# Example zecd configuration"),
            "example config keeps its explanatory header"
        );
        assert!(
            EXAMPLE_CONFIG
                .lines()
                .filter(|l| l.trim_start().starts_with('#'))
                .count()
                > 100,
            "comments survive - the whole reason this is embedded rather than serialized"
        );
        let doc: toml::Value = toml::from_str(EXAMPLE_CONFIG).expect("valid TOML");
        assert!(doc.get("wallets").is_some(), "declares a wallet section");
        assert!(doc.get("backend").is_some(), "declares a backend section");
    }

    #[test]
    fn writes_to_the_requested_path() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zecd.toml");
        run(&args(Some(path.to_str().unwrap()), false)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), EXAMPLE_CONFIG);
    }

    #[test]
    fn refuses_to_clobber_an_existing_file_without_force() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("zecd.toml");
        std::fs::write(&path, "network = \"main\"\n").unwrap();

        let err = run(&args(Some(path.to_str().unwrap()), false)).unwrap_err();
        assert!(
            err.to_string().contains("--force"),
            "the error names the escape hatch: {err}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "network = \"main\"\n",
            "the existing config is left untouched"
        );

        run(&args(Some(path.to_str().unwrap()), true)).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), EXAMPLE_CONFIG);
    }

    /// No `-o` and `-o -` both mean stdout; anything else is a real path.
    #[test]
    fn dash_and_absent_output_mean_stdout() {
        assert_eq!(output_path(&args(None, false)), None);
        assert_eq!(output_path(&args(Some("-"), false)), None);
        assert_eq!(
            output_path(&args(Some("./zecd.toml"), false)),
            Some(Path::new("./zecd.toml"))
        );
    }
}
