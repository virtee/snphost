// SPDX-License-Identifier: Apache-2.0

use super::*;

use cert::{fetch::hashsticks::vlek_hashsticks_url, fetch::vek::vek_url, Endorsement};

#[derive(Subcommand)]
pub enum Show {
    /// Show the current number of guests
    Guests,

    /// Show the platform identifier
    Identifier,

    /// Show the current platform and reported TCB version
    Tcb,

    /// Show the VCEK DER download URL
    VcekUrl,

    /// Show the VLEK DER download URL
    VlekUrl,

    /// Show the VLEK hashsticks download URL
    HashsticksURL,

    /// Show the platform's firmware version
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
            let url = vek_url(Endorsement::Vcek)?;

            println!("{}", url);
        }
        Show::VlekUrl => println!("{}", vek_url(Endorsement::Vlek)?),
        Show::HashsticksURL => println!("{}", vlek_hashsticks_url()?),
        Show::Version => println!("{}.{}", status.version.0, status.version.1),
    }

    Ok(())
}
