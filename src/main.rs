// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

mod cert;
mod config;
mod processor;
mod show;

mod ok;

use cert::{export, fetch, import, verify};

use anyhow::{Context, Result};
use sev::firmware::host::*;
use structopt::StructOpt;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[derive(StructOpt)]
struct SnpHost {
    #[structopt(subcommand)]
    pub cmd: SnpHostCmd,

    #[structopt(short, long, about = "Don't print anything to the console")]
    pub quiet: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(StructOpt)]
#[structopt(author = AUTHORS, version = VERSION, about = "Utilities for managing the SEV-SNP environment")]
enum SnpHostCmd {
    #[structopt(about = "Display information about the SEV-SNP platform")]
    Show(show::Show),

    #[structopt(
        about = "Export a certificate chain from a kernel format file to a given directory"
    )]
    Export(export::Export),

    #[structopt(about = "Import a certificate chain to a file")]
    Import(import::Import),

    #[structopt(about = "Probe system for SEV-SNP support")]
    Ok,

    #[structopt(about = "Modify the SNP configuration")]
    Config(config::ConfigCmd),

    #[structopt(about = "Verify a certificate chain")]
    Verify(verify::Verify),

    #[structopt(about = "Retrieve content from the AMD Key Distribution Server (KDS)")]
    Fetch(fetch::Fetch),

    #[structopt(about = "Commit current firmware and TCB versions to PSP")]
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

    let snphost = SnpHost::from_args();
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
