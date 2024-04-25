// SPDX-License-Identifier: Apache-2.0

use super::*;

// Different config commands
#[derive(Subcommand)]
pub enum ConfigCmd {
    /// Change the Platform Config (TCB and Mask chip) to the provided values
    Set(set::Args),

    /// Reset the SEV-SNP Config to the last comitted version
    #[command(subcommand)]
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
        /// Bootloader version
        /// (Unsigned 8-bit Integer)
        #[arg(value_name = "bootloader", required = true)]
        pub bootloader: u8,

        /// PSP OS version (Unsigned 8-bit Integer)
        #[arg(value_name = "tee", required = true)]
        pub tee: u8,

        /// Version of the SNP firmware (Unsigned 8-bit Integer)
        #[arg(value_name = "snp-fw", required = true)]
        pub snp_fw: u8,

        /// Microcode Patch level of all the cores (Unsigned 8-bit Integer)
        #[arg(value_name = "microcode", required = true)]
        pub microcode: u8,

        /// Change mask chip bit field (Unsigned 32-bit Integer) values by providing decimal representation of desired change (0-3). Bit[0]: CHIP_ID, Bit[1]: CHIP_KEY. Both are disabled by default
        #[arg(value_name = "mask-chip", required = true)]
        mask_chip: u32,
    }

    pub fn set_config(args: Args) -> Result<()> {
        // Create Tcb with provided values
        let tcb = TcbVersion::new(args.bootloader, args.tee, args.snp_fw, args.microcode);

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
