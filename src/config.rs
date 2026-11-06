// SPDX-License-Identifier: Apache-2.0

use super::*;
use crate::processor::ProcessorGeneration;
use anyhow::anyhow;

// Different config commands
#[derive(Subcommand)]
pub enum ConfigCmd {
    /// Change the Platform Config (TCB and Mask chip) to the provided values
    Set(set::Args),

    /// Reset the SEV-SNP Config to the last comitted version
    Reset,
}

pub fn cmd(cmd: ConfigCmd) -> Result<()> {
    match cmd {
        ConfigCmd::Set(args) => set::set_config(args),
        ConfigCmd::Reset => reset::reset_config(),
    }
}

mod set {
    use super::*;

    #[derive(Parser)]
    pub struct Args {
        /// PSP OS version (Unsigned 8-bit Integer).
        #[arg(long, value_name = "tee", required = true)]
        pub tee: u8,

        /// Version of the SNP firmware (Unsigned 8-bit Integer).
        #[arg(long, value_name = "snp-fw", required = true)]
        pub snp_fw: u8,

        /// Change mask chip bit field (Unsigned 32-bit Integer) values by providing decimal representation of desired change (0-3). Bit[0]: CHIP_ID, Bit[1]: CHIP_KEY. Both are disabled by default.
        #[arg(long, value_name = "mask-chip", required = true)]
        mask_chip: u32,

        /// Bootloader version (Unsigned 8-bit Integer).
        /// Required on Milan, Genoa, Bergamo, Siena, and Turin. Not used on Venice.
        #[arg(long, value_name = "bootloader")]
        pub bootloader: Option<u8>,

        /// Microcode patch level of all the cores (Unsigned 8-bit Integer).
        /// Required on Milan, Genoa, Bergamo, Siena, and Turin. Not used on Venice.
        #[arg(long, value_name = "microcode")]
        pub microcode: Option<u8>,

        /// FMC firmware version (Unsigned 8-bit Integer).
        /// Required on Turin and Venice.
        #[arg(long, value_name = "fmc")]
        fmc: Option<u8>,
    }

    pub fn set_config(args: Args) -> Result<()> {
        let generation = ProcessorGeneration::current()?;
        let tcb = tcb_for_generation(&generation, &args)?;

        // Create Mask Chip with provided value
        let mask_chip = MaskId(args.mask_chip);

        // Create new Config
        let config = Config::new(tcb, mask_chip);

        // Change Config
        let mut fw = firmware()?;
        fw.snp_set_config(config)
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
            .context("Error setting a new snp config")
    }

    fn tcb_for_generation(generation: &ProcessorGeneration, args: &Args) -> Result<TcbVersion> {
        match generation {
            ProcessorGeneration::Milan
            | ProcessorGeneration::Genoa
            | ProcessorGeneration::Bergamo
            | ProcessorGeneration::Siena => {
                reject_field(args.fmc, generation, "FMC")?;
                Ok(TcbVersion::new(
                    None,
                    Some(require_field(args.bootloader, generation, "bootloader")?),
                    args.tee,
                    args.snp_fw,
                    Some(require_field(args.microcode, generation, "microcode")?),
                ))
            }
            ProcessorGeneration::Turin => Ok(TcbVersion::new(
                Some(require_field(args.fmc, generation, "FMC")?),
                Some(require_field(args.bootloader, generation, "bootloader")?),
                args.tee,
                args.snp_fw,
                Some(require_field(args.microcode, generation, "microcode")?),
            )),
            ProcessorGeneration::Venice => {
                reject_field(args.bootloader, generation, "bootloader")?;
                reject_field(args.microcode, generation, "microcode")?;
                Ok(TcbVersion::new(
                    Some(require_field(args.fmc, generation, "FMC")?),
                    None,
                    args.tee,
                    args.snp_fw,
                    None,
                ))
            }
        }
    }

    fn require_field(
        value: Option<u8>,
        generation: &ProcessorGeneration,
        name: &str,
    ) -> Result<u8> {
        value.ok_or_else(|| {
            anyhow!("{generation} generation processor requires {name} version when setting TCB")
        })
    }

    fn reject_field(value: Option<u8>, generation: &ProcessorGeneration, name: &str) -> Result<()> {
        if value.is_some() {
            Err(anyhow!(
                "{generation} generation processor does not use {name} when setting TCB"
            ))
        } else {
            Ok(())
        }
    }
}

mod reset {
    use super::*;
    pub fn reset_config() -> Result<()> {
        let mut fw = firmware()?;

        // Provide confing to set_config with all 0s
        fw.snp_set_config(Config::default())
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
            .context("Error resetting SEV-SNP configuration")
    }
}
