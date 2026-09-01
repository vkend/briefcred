//! The on-disk layout, resolved in exactly one place.
//!
//! Every other crate asks [`Paths`] where things live rather than joining
//! path fragments itself. `BRIEFCRED_HOME` overrides the entire layout, which
//! is how tests stay off the real user directories.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

/// Environment variable that relocates the whole layout, including the socket.
pub const HOME_ENV: &str = "BRIEFCRED_HOME";

/// The platforms briefcred knows how to lay itself out on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Platform {
    /// `~/Library/Application Support/briefcred`.
    MacOs,
    /// XDG data directory, with the socket under `XDG_RUNTIME_DIR`.
    Linux,
}

impl Platform {
    /// The platform this binary was compiled for.
    ///
    /// Returns `None` on targets briefcred has no layout for.
    pub fn current() -> Option<Platform> {
        #[cfg(target_os = "macos")]
        {
            Some(Platform::MacOs)
        }
        #[cfg(target_os = "linux")]
        {
            Some(Platform::Linux)
        }
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        {
            None
        }
    }
}

/// Resolved absolute locations of everything briefcred owns on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    root: PathBuf,
    sock: PathBuf,
}

impl Paths {
    /// Resolve the layout for the running platform from the process environment.
    pub fn discover() -> Result<Paths> {
        let platform = Platform::current().ok_or_else(|| {
            Error::Layout(format!(
                "unsupported platform `{}`; set {HOME_ENV} to choose a layout",
                std::env::consts::OS
            ))
        })?;
        Paths::resolve(platform, &|key| std::env::var_os(key))
    }

    /// Resolve the layout for `platform` against an arbitrary environment.
    ///
    /// Split out from [`Paths::discover`] so the Linux layout is unit-testable
    /// from a macOS host and vice versa.
    pub fn resolve(platform: Platform, env: &dyn Fn(&str) -> Option<OsString>) -> Result<Paths> {
        if let Some(root) = non_empty(env(HOME_ENV)) {
            let root = PathBuf::from(root);
            let sock = root.join("sock");
            return Ok(Paths { root, sock });
        }

        match platform {
            Platform::MacOs => {
                let root = home(env)?
                    .join("Library")
                    .join("Application Support")
                    .join("briefcred");
                let sock = root.join("sock");
                Ok(Paths { root, sock })
            }
            Platform::Linux => {
                let root = match non_empty(env("XDG_DATA_HOME")) {
                    Some(data) => PathBuf::from(data).join("briefcred"),
                    None => home(env)?.join(".local").join("share").join("briefcred"),
                };
                let sock = match non_empty(env("XDG_RUNTIME_DIR")) {
                    Some(run) => PathBuf::from(run).join("briefcred").join("sock"),
                    None => root.join("sock"),
                };
                Ok(Paths { root, sock })
            }
        }
    }

    /// The directory holding everything else.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// The daemon's Unix domain socket.
    pub fn sock(&self) -> &Path {
        &self.sock
    }

    /// Directory scanned for `*.yaml` profiles.
    pub fn profiles_dir(&self) -> PathBuf {
        self.root.join("profiles")
    }

    /// Directory holding rotated JSONL audit logs.
    pub fn audit_dir(&self) -> PathBuf {
        self.root.join("audit")
    }

    /// Directory holding the per-machine root CA material.
    pub fn ca_dir(&self) -> PathBuf {
        self.root.join("ca")
    }

    /// The daemon's configuration file.
    pub fn daemon_toml(&self) -> PathBuf {
        self.root.join("daemon.toml")
    }
}

fn non_empty(value: Option<OsString>) -> Option<OsString> {
    value.filter(|v| !v.is_empty())
}

fn home(env: &dyn Fn(&str) -> Option<OsString>) -> Result<PathBuf> {
    non_empty(env("HOME"))
        .map(PathBuf::from)
        .ok_or_else(|| Error::Layout(format!("HOME is unset; set {HOME_ENV} instead")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn env_of(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<OsString> {
        let map: BTreeMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        move |key| map.get(key).map(OsString::from)
    }

    #[test]
    fn macos_layout_hangs_off_application_support() {
        let env = env_of(&[("HOME", "/Users/ada")]);
        let paths = Paths::resolve(Platform::MacOs, &env).unwrap();
        assert_eq!(
            paths.root(),
            Path::new("/Users/ada/Library/Application Support/briefcred")
        );
        assert_eq!(
            paths.sock(),
            Path::new("/Users/ada/Library/Application Support/briefcred/sock")
        );
        assert!(paths.profiles_dir().ends_with("briefcred/profiles"));
        assert!(paths.audit_dir().ends_with("briefcred/audit"));
        assert!(paths.ca_dir().ends_with("briefcred/ca"));
        assert!(paths.daemon_toml().ends_with("briefcred/daemon.toml"));
    }

    #[test]
    fn linux_layout_uses_xdg_data_home_and_runtime_dir() {
        let env = env_of(&[
            ("HOME", "/home/ada"),
            ("XDG_DATA_HOME", "/home/ada/.data"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
        ]);
        let paths = Paths::resolve(Platform::Linux, &env).unwrap();
        assert_eq!(paths.root(), Path::new("/home/ada/.data/briefcred"));
        assert_eq!(paths.sock(), Path::new("/run/user/1000/briefcred/sock"));
    }

    #[test]
    fn linux_layout_falls_back_to_dot_local_share() {
        let env = env_of(&[("HOME", "/home/ada")]);
        let paths = Paths::resolve(Platform::Linux, &env).unwrap();
        assert_eq!(paths.root(), Path::new("/home/ada/.local/share/briefcred"));
        assert_eq!(
            paths.sock(),
            Path::new("/home/ada/.local/share/briefcred/sock")
        );
    }

    #[test]
    fn briefcred_home_overrides_every_platform() {
        let env = env_of(&[
            ("HOME", "/home/ada"),
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            (HOME_ENV, "/tmp/t1"),
        ]);
        for platform in [Platform::MacOs, Platform::Linux] {
            let paths = Paths::resolve(platform, &env).unwrap();
            assert_eq!(paths.root(), Path::new("/tmp/t1"));
            assert_eq!(paths.sock(), Path::new("/tmp/t1/sock"));
            assert_eq!(paths.profiles_dir(), Path::new("/tmp/t1/profiles"));
        }
    }

    #[test]
    fn empty_env_values_are_treated_as_unset() {
        let env = env_of(&[("HOME", "/home/ada"), (HOME_ENV, ""), ("XDG_DATA_HOME", "")]);
        let paths = Paths::resolve(Platform::Linux, &env).unwrap();
        assert_eq!(paths.root(), Path::new("/home/ada/.local/share/briefcred"));
    }

    #[test]
    fn missing_home_is_an_error_that_names_the_override() {
        let env = env_of(&[]);
        let err = Paths::resolve(Platform::MacOs, &env).unwrap_err();
        assert!(err.to_string().contains(HOME_ENV), "{err}");
    }
}
