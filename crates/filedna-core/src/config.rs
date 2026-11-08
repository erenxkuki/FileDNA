use crate::Result;
use crate::types::Config;
use std::path::PathBuf;

pub fn default_config() -> Config {
    Config::default()
}

pub fn config_path() -> PathBuf {
    // Local-first: store in user data dir if possible, else current.
    if let Some(base) = dirs_base() {
        base.join("filedna").join("config.toml")
    } else {
        PathBuf::from("filedna.toml")
    }
}

fn dirs_base() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var_os("APPDATA").map(PathBuf::from)
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var_os("HOME")
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos")))]
    {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
    }
}

pub fn load_config() -> Config {
    let p = config_path();
    if p.exists() {
        if let Ok(s) = std::fs::read_to_string(&p) {
            if let Ok(c) = toml::from_str(&s) {
                return c;
            }
        }
    }
    Config::default()
}

pub fn save_config(cfg: &Config) -> Result<()> {
    let p = config_path();
    if let Some(parent) = p.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let s = toml::to_string_pretty(cfg).map_err(|e| crate::FileDnaError::Unknown(e.to_string()))?;
    std::fs::write(&p, s)?;
    Ok(())
}
