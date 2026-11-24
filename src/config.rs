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
        /// Changes only this reported TCB field.
        #[arg(long, value_name = "tee")]
        pub tee: Option<u8>,

        /// Version of the SNP firmware (Unsigned 8-bit Integer).
        /// Changes only this reported TCB field.
        #[arg(long, value_name = "snp-fw")]
        pub snp_fw: Option<u8>,

        /// Change mask chip bit field (Unsigned 32-bit Integer) values by providing decimal representation of desired change (0-3). Bit[0]: CHIP_ID, Bit[1]: CHIP_KEY. Both are disabled by default.
        #[arg(long, value_name = "mask-chip")]
        mask_chip: Option<u32>,

        /// Bootloader version (Unsigned 8-bit Integer).
        /// Changes only this reported TCB field. Invalid on Venice.
        #[arg(long, value_name = "bootloader")]
        pub bootloader: Option<u8>,

        /// Microcode patch level of all the cores (Unsigned 8-bit Integer).
        /// Changes only this reported TCB field. Invalid on Venice.
        #[arg(long, value_name = "microcode")]
        pub microcode: Option<u8>,

        /// FMC firmware version (Unsigned 8-bit Integer).
        /// Changes only this reported TCB field. Invalid before Turin.
        #[arg(long, value_name = "fmc")]
        fmc: Option<u8>,
    }

    pub fn set_config(args: Args) -> Result<()> {
        if args.tee.is_none()
            && args.snp_fw.is_none()
            && args.mask_chip.is_none()
            && args.bootloader.is_none()
            && args.microcode.is_none()
            && args.fmc.is_none()
        {
            return Err(anyhow!("no config fields were provided"));
        }

        let generation = ProcessorGeneration::current()?;
        reject_invalid_fields(&generation, &args)?;

        let status = snp_platform_status()?;
        let tcb = tcb_for_generation(&generation, &args, status.reported_tcb_version);
        let mask_chip = match args.mask_chip {
            Some(mask_chip) => MaskId(mask_chip),
            None => mask_id_from_policy(status.platform_policy),
        };

        let mut fw = firmware()?;
        fw.snp_set_config(Config::new(tcb, mask_chip))
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
            .context("Error setting a new snp config")
    }

    fn reject_invalid_fields(generation: &ProcessorGeneration, args: &Args) -> Result<()> {
        match generation {
            ProcessorGeneration::Milan
            | ProcessorGeneration::Genoa
            | ProcessorGeneration::Bergamo
            | ProcessorGeneration::Siena => reject_field(args.fmc, generation, "fmc"),
            ProcessorGeneration::Turin | ProcessorGeneration::Sorano => Ok(()),
            ProcessorGeneration::Venice => {
                reject_field(args.bootloader, generation, "bootloader")?;
                reject_field(args.microcode, generation, "microcode")
            }
        }
    }

    fn tcb_for_generation(
        generation: &ProcessorGeneration,
        args: &Args,
        mut tcb: TcbVersion,
    ) -> TcbVersion {
        if let Some(tee) = args.tee {
            tcb.tee = tee;
        }
        if let Some(snp) = args.snp_fw {
            tcb.snp = snp;
        }

        match generation {
            ProcessorGeneration::Milan
            | ProcessorGeneration::Genoa
            | ProcessorGeneration::Bergamo
            | ProcessorGeneration::Siena => {
                if let Some(bootloader) = args.bootloader {
                    tcb.bootloader = Some(bootloader);
                }
                if let Some(microcode) = args.microcode {
                    tcb.microcode = Some(microcode);
                }
                tcb.fmc = None;
            }
            ProcessorGeneration::Turin | ProcessorGeneration::Sorano => {
                if let Some(bootloader) = args.bootloader {
                    tcb.bootloader = Some(bootloader);
                }
                if let Some(microcode) = args.microcode {
                    tcb.microcode = Some(microcode);
                }
                if let Some(fmc) = args.fmc {
                    tcb.fmc = Some(fmc);
                }
            }
            ProcessorGeneration::Venice => {
                if let Some(fmc) = args.fmc {
                    tcb.fmc = Some(fmc);
                }
                tcb.bootloader = None;
                tcb.microcode = None;
            }
        }

        tcb
    }

    fn reject_field(value: Option<u8>, generation: &ProcessorGeneration, name: &str) -> Result<()> {
        if value.is_some() {
            Err(anyhow!("invalid field {name} for {generation}"))
        } else {
            Ok(())
        }
    }

    fn mask_id_from_policy(policy: PlatformPolicy) -> MaskId {
        let mut mask = 0u32;
        if policy.mask_chip_id() {
            mask |= 1;
        }
        if policy.mask_chip_key() {
            mask |= 2;
        }
        MaskId(mask)
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
