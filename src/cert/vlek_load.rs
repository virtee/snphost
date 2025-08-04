// SPDX-License-Identifier: Apache-2.0

use super::*;
use sev::{firmware::host::WrappedVlekHashstick, Generation};
use std::{fs::read, path::PathBuf};

use anyhow::{bail, Context, Result};

#[derive(Parser)]
pub struct VlekLoad {
    /// File where the VLEK hashshtick is stored.
    #[arg(value_name = "hashstick-file", required = true)]
    pub hashstick_file: PathBuf,
}

pub fn cmd(vlek_load: VlekLoad) -> Result<()> {
    if !vlek_load.hashstick_file.exists() {
        bail!(format!(
            "path {} does not exist",
            vlek_load.hashstick_file.display()
        ));
    }

    let hashstick_bytes =
        read(&vlek_load.hashstick_file).context("Failed to read VLEK hashshtick file")?;

    let generation = Generation::identify_host_generation()?;

    let hashstick = WrappedVlekHashstick::from_bytes(&hashstick_bytes, generation)
        .context("Failed to parse VLEK hashshtick")?;

    let mut buffer: [u8; 432] = [0; 432];
    hashstick.write_bytes(&mut buffer[..], generation)?;

    // Load the VLEK hashshtick into the firmware.
    let mut fw = firmware()?;

    fw.snp_vlek_load(buffer.as_slice())
        .map_err(|e| anyhow::anyhow!(format!("{:}", e)))
        .context("Error loading VLEK hashshtick")?;

    Ok(())
}
