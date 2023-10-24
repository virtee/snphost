// SPDX-License-Identifier: Apache-2.0

use super::*;

pub fn cmd() -> Result<()> {
    let mut fw = firmware()?;

    fw.snp_reset_config()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("error resetting SEV-SNP configuration")
}
