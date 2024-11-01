// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

use clap::{arg, Parser, Subcommand};

use super::*;

pub(crate) fn firmware() -> Result<Firmware> {
    Firmware::open().context("unable to open /dev/sev")
}

pub(crate) fn snp_platform_status() -> anyhow::Result<SnpPlatformStatus> {
    firmware()?
        .snp_platform_status()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to retrieve SNP platform status")
}

pub(crate) fn sev_platform_status() -> anyhow::Result<Status> {
    firmware()?
        .platform_status()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to retrieve SEV platform status")
}

// Commit command
mod commit {
    use crate::cli::firmware;
    pub fn cmd() -> anyhow::Result<()> {
        firmware()?.snp_commit()?;
        Ok(())
    }
}

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct SnpHost {
    #[command(subcommand)]
    pub cmd: SnpHostCmd,

    /// Don't print anything to the console
    #[arg(short, long, default_value_t = false)]
    pub quiet: bool,
}

#[allow(clippy::large_enum_variant)]
/// Utilities for managing the SEV-SNP environment
#[derive(Subcommand)]
pub enum SnpHostCmd {
    /// Display information about the SEV-SNP platform
    #[command(subcommand)]
    Show(show::Show),

    /// Export a certificate chain from a kernel format file to a given directory
    Export(export::Export),

    /// Import a certificate chain to a file
    Import(import::Import),

    /// Probe system for SEV-SNP support
    Ok,

    /// Modify the SNP configuration
    #[command(subcommand)]
    Config(config::ConfigCmd),

    /// Verify a certificate chain
    Verify(verify::Verify),

    /// Retrieve content from the AMD Key Distribution Server (KDS)
    #[command(subcommand)]
    Fetch(fetch::Fetch),

    /// Commit current firmware and TCB versions to PSP
    Commit,
}

impl SnpHostCmd {
    pub fn handle(self, quiet: bool) -> Result<()> {
        match self {
            Self::Show(show) => show::cmd(show),
            Self::Export(export) => export::cmd(export),
            Self::Import(import) => import::cmd(import),
            Self::Ok => ok::cmd(quiet),
            Self::Config(subcmd) => config::cmd(subcmd),
            Self::Verify(verify) => verify::cmd(verify, quiet),
            Self::Fetch(fetch) => fetch::cmd(fetch),
            Self::Commit => commit::cmd(),
        }
    }
}
