use anyhow::{anyhow, Result};
use crate::config::TorConfig;
use std::process::Command;

pub struct TorService {
    config: TorConfig,
}

impl TorService {
    pub fn new(config: TorConfig) -> Self {
        Self { config }
    }

    pub fn bootstrap(&self) -> Result<()> {
        if !self.config.enabled {
            return Ok(());
        }

        let service_dir = &self.config.service_dir;
        std::fs::create_dir_all(service_dir)?;

        let torrc_path = service_dir.join("torrc");
        if !torrc_path.exists() {
            // SECURITY: Tor v3 hidden service with hardening options
            // HiddenServiceVersion 3 - Use only v3 addresses (more secure)
            // HiddenServiceMaxStreams - Limit concurrent streams
            // CircuitIsolation - Require new circuit for each connection
            // HiddenServiceAnonymousMode - Enable anonymity mode
            let torrc_content = format!(
                "HiddenServiceDir {}\n\
                 HiddenServiceVersion 3\n\
                 HiddenServicePort {} 127.0.0.1:{}\n\
                 HiddenServiceMaxStreams 1024\n\
                 CircuitIsolation 1\n\
                 HiddenServiceAnonymousMode 1\n\
                 IsolateSOCKSAuth 1\n",
                service_dir.display(),
                self.config.port,
                self.config.port,
            );
            std::fs::write(&torrc_path, torrc_content)?;
        }

        Ok(())
    }

    pub fn get_onion_address(&self) -> Result<String> {
        let hostname_path = self.config.service_dir.join("hostname");
        if hostname_path.exists() {
            let address = std::fs::read_to_string(&hostname_path)?
                .trim()
                .to_string();
            return Ok(address);
        }

        Err(anyhow!("Tor hostname file not found. Has Tor started?"))
    }

    pub fn start_tor_process(&self) -> Result<std::process::Child> {
        let child = Command::new("tor")
            .arg("-f")
            .arg(self.config.service_dir.join("torrc"))
            .spawn()
            .map_err(|e| anyhow!("Failed to start Tor: {}. Is tor installed?", e))?;

        Ok(child)
    }

    pub fn cleanup_old_keys(&self) -> Result<()> {
        // Only keep the onion key, nothing else
        let service_dir = &self.config.service_dir;
        if service_dir.exists() {
            for entry in std::fs::read_dir(service_dir)? {
                let path = entry?.path();
                if let Some(name) = path.file_name() {
                    let name = name.to_string_lossy();
                    // Keep only essential files
                    if name != "hostname"
                        && name != "hs_ed25519_secret_key"
                        && name != "hs_ed25519_public_key"
                        && name != "torrc"
                    {
                        std::fs::remove_file(&path).ok();
                    }
                }
            }
        }
        Ok(())
    }
}
