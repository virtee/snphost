// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

use anyhow::{Context, Result};
use sev::firmware::host::*;
use structopt::StructOpt;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[derive(StructOpt)]
struct SnpHost {
    #[structopt(subcommand)]
    pub cmd: SnpHostCmd,
}

#[allow(clippy::large_enum_variant)]
#[derive(StructOpt)]
#[structopt(author = AUTHORS, version = VERSION, about = "Utilities for managing the SEV-SNP environment")]
enum SnpHostCmd {
    #[structopt(about = "Display information about the SEV-SNP platform")]
    Show(show::Show),
}

fn firmware() -> Result<Firmware> {
    Firmware::open().context("unable to open /dev/sev")
}

fn platform_status() -> Result<SnpPlatformStatus> {
    firmware()?
        .snp_platform_status()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to retrieve SNP platform status")
}

fn main() -> Result<()> {
    env_logger::init();

    let snphost = SnpHost::from_args();
    match snphost.cmd {
        SnpHostCmd::Show(show) => show::cmd(show),
    }
}

mod show {
    use super::*;

    #[derive(StructOpt)]
    pub enum Generation {
        #[structopt(about = "Milan generation of SEV-SNP processors")]
        Milan,

        #[structopt(about = "Genoa generation of SEV-SNP processors")]
        Genoa,
    }

    impl ToString for Generation {
        fn to_string(&self) -> String {
            let s = match self {
                Self::Milan => "Milan",
                Self::Genoa => "Genoa",
            };

            s.to_string()
        }
    }

    #[derive(StructOpt)]
    pub enum Show {
        #[structopt(about = "Show the current number of guests")]
        Guests,

        #[structopt(about = "Show the platform identifier")]
        Identifier,

        #[structopt(about = "Show the current platform and reported TCB version")]
        Tcb,

        #[structopt(about = "Show the VCEK DER download URL")]
        VcekUrl(Generation),

        #[structopt(about = "Show the platform's firmware version")]
        Version,
    }

    pub fn cmd(show: Show) -> Result<()> {
        let status = platform_status()?;

        match show {
            Show::Guests => println!("{}", status.guest_count),
            Show::Identifier => {
                let id = firmware()?
                    .get_identifier()
                    .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
                    .context("error fetching identifier")?;

                println!("{}", id);
            }
            Show::Tcb => println!(
                "Reported TCB: {}\nPlatform TCB: {}",
                status.reported_tcb_version, status.platform_tcb_version
            ),
            Show::VcekUrl(gen) => {
                let id = firmware()?
                    .get_identifier()
                    .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
                    .context("error fetching identifier")?;
                let status = platform_status()?;

                println!("https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                         gen.to_string(), id, status.platform_tcb_version.bootloader,
                         status.platform_tcb_version.tee,
                         status.platform_tcb_version.snp,
                         status.platform_tcb_version.microcode);
            }
            Show::Version => println!("{}", status.version),
        }

        Ok(())
    }
}
