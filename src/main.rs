// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

mod cert;
mod config;
mod processor;
mod show;

mod ok;

use cert::{export, fetch, import, verify};

use anyhow::{Context, Result};
use clap::{arg, Parser, Subcommand, ValueEnum};
use sev::firmware::host::*;

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct SnpHost {
    #[command(subcommand)]
    pub cmd: SnpHostCmd,

    /// Don't print anything to the console
    #[arg(short, long, default_value_t = false)]
    pub quiet: bool,
}

#[allow(clippy::large_enum_variant)]
/// Utilities for managing the SEV-SNP environment
#[derive(Subcommand)]
enum SnpHostCmd {
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

// Commit command
mod commit {
    use super::*;
    pub fn cmd() -> Result<()> {
        firmware()?.snp_commit()?;
        Ok(())
    }
}

fn firmware() -> Result<Firmware> {
    Firmware::open().context("unable to open /dev/sev")
}

fn snp_platform_status() -> Result<SnpPlatformStatus> {
    firmware()?
        .snp_platform_status()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to retrieve SNP platform status")
}

fn sev_platform_status() -> Result<Status> {
    firmware()?
        .platform_status()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to retrieve SEV platform status")
}

fn main() -> Result<()> {
    env_logger::init();

    let snphost = SnpHost::parse();
    let result = match snphost.cmd {
        SnpHostCmd::Show(show) => show::cmd(show),
        SnpHostCmd::Export(export) => export::cmd(export),
        SnpHostCmd::Import(import) => import::cmd(import),
        SnpHostCmd::Ok => ok::cmd(snphost.quiet),
        SnpHostCmd::Config(subcmd) => config::cmd(subcmd),
        SnpHostCmd::Verify(verify) => verify::cmd(verify, snphost.quiet),
        SnpHostCmd::Fetch(fetch) => fetch::cmd(fetch),
        SnpHostCmd::Commit => commit::cmd(),
    };

    if !snphost.quiet {
        if let Err(ref e) = result {
            eprintln!("ERROR: {}", e);
        }
    }

    result
}
