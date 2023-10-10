// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use std::arch::x86_64;

pub enum ProcessorGeneration {
    Milan,
    Genoa,
}

impl ProcessorGeneration {
    // Get the SEV generation of the processor currently running on the machine.
    // To do this, we execute a CPUID (label 0x80000001) and read the EAX
    // register as an array of bytes (each byte representing 8 bits of a 32-bit
    // value, thus the array is 4 bytes long). The formatting for these values is
    // as follows:
    //
    //  Base model:         bits 4:7
    //  Base family:        bits 8:11
    //  Extended model:     bits 16:19
    //  Extended family:    bits 20:27
    //
    // Extract the bit values from the array, and use them to calculate the MODEL
    // and FAMILY of the processor.
    //
    // The family calculation is as follows:
    //
    //      FAMILY = Base family + Extended family
    //
    // The model calculation is a follows:
    //
    //      MODEL = Base model | (Extended model << 4)
    //
    // Compare these values with the models and families of known processor generations to
    // determine which generation the current processor is a part of.
    pub fn current() -> Result<Self> {
        let cpuid = unsafe { x86_64::__cpuid(0x8000_0001) };
        let bytes: Vec<u8> = cpuid.eax.to_le_bytes().to_vec();

        let base_model = (bytes[0] & 0xF0) >> 4;
        let base_family = bytes[1] & 0x0F;

        let ext_model = bytes[2] & 0x0F;

        let ext_family = {
            let low = (bytes[2] & 0xF0) >> 4;
            let high = (bytes[3] & 0x0F) << 4;

            low | high
        };

        let model = (ext_model << 4) | base_model;
        let family = base_family + ext_family;

        let id = (model, family);

        let milan = (1, 25);
        let genoa = (17, 25);

        if id == milan {
            return Ok(Self::Milan);
        } else if id == genoa {
            return Ok(Self::Genoa);
        }

        Err(anyhow!("processor is not of a known SEV-SNP generation"))
    }
}

impl ToString for ProcessorGeneration {
    fn to_string(&self) -> String {
        let sstr = match self {
            Self::Milan => "Milan",
            Self::Genoa => "Genoa",
        };

        sstr.to_string()
    }
}
