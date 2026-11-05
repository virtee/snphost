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
    Tcb(TcbArgs),

    /// Show the VCEK DER download URL
    VcekUrl,

    /// Show the VLEK DER download URL
    VlekUrl,

    /// Show the VLEK hashsticks download URL
    HashsticksURL,

    /// Show the platform's firmware version
    Version,
}

#[derive(Parser)]
pub struct TcbArgs {
    /// Controls how the TCB versions are rendered
    #[arg(short, long, value_enum, default_value_t = OutputFormat::Default)]
    output: OutputFormat,
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
        Show::Tcb(args) => match args.output {
            OutputFormat::Default => println!(
                "Reported TCB: {}\nPlatform TCB: {}",
                status.reported_tcb_version, status.platform_tcb_version
            ),
            OutputFormat::Json => {
                let output = serde_json::json!({
                    "reported_tcb": tcb_json(&status.reported_tcb_version),
                    "platform_tcb": tcb_json(&status.platform_tcb_version),
                });

                serde_json::to_writer_pretty(std::io::stdout(), &output)?;
                println!();
            }
        },
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

/// JSON representation of a TCB version
fn tcb_json(tcb: &TcbVersion) -> serde_json::Value {
    serde_json::json!({
        "fmc": tcb.fmc,
        "bootloader": tcb.bootloader,
        "tee": tcb.tee,
        "snp_fw": tcb.snp,
        "microcode": tcb.microcode,
    })
}
