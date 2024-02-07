// SPDX-License-Identifier: Apache-2.0

use super::*;

// Different config commands
#[derive(StructOpt)]
pub enum ConfigCmd {
    #[structopt(about = "Change the Platform Config (TCB and Mask chip) to the provided values")]
    Set(set::Args),

    #[structopt(about = "Reset the SEV-SNP Config to the last comitted version")]
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

    #[derive(StructOpt)]
    pub struct Args {
        #[structopt(help = "Bootloader: Bootloader version")]
        pub bootloader: u8,

        #[structopt(help = "TEE: PSP OS version")]
        pub tee: u8,

        #[structopt(help = "SNP FIRMWARE: Version of the SNP firmware")]
        pub snp_fw: u8,

        #[structopt(help = "MICROCODE: Patch level of all the cores")]
        pub microcode: u8,

        #[structopt(
            help = "MASK CHIP: Change mask chip bit field values by providing decimal representation of desired change (0-3). Bit[0]: CHIP_ID, Bit[1]: CHIP_KEY. Both are disabled by default"
        )]
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
