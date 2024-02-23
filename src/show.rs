// SPDX-License-Identifier: Apache-2.0

use super::*;

use cert::fetch::vcek::vcek_url;

#[derive(StructOpt)]
pub enum Show {
    #[structopt(about = "Show the current number of guests")]
    Guests,

    #[structopt(about = "Show the platform identifier")]
    Identifier,

    #[structopt(about = "Show the current platform and reported TCB version")]
    Tcb,

    #[structopt(about = "Show the VCEK DER download URL")]
    VcekUrl,

    #[structopt(about = "Show the platform's firmware version")]
    Version,
}

pub fn cmd(show: Show) -> Result<()> {
    let status = snp_platform_status()?;

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
        Show::VcekUrl => {
            let url = vcek_url()?;

            println!("{}", url);
        }
        Show::Version => println!("{}", status.version),
    }

    Ok(())
}
