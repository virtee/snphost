// SPDX-License-Identifier: Apache-2.0

use std::fmt;

use super::*;

pub(crate) mod ca;
pub(crate) mod crl;
pub(crate) mod vcek;
use anyhow::Result;

#[derive(Subcommand)]
pub enum Fetch {
    /// Fetches the VCEK from the KDS
    Vcek(vcek::Vcek),

    /// Fetches the CA from the KDS
    Ca(ca::Ca),

    /// Fetches the CRL from the KDS
    Crl(crl::Crl),
}

pub fn cmd(fetch: Fetch) -> Result<()> {
    match fetch {
        Fetch::Vcek(vcek) => vcek::cmd(vcek),
        Fetch::Ca(ca) => ca::cmd(ca),
        Fetch::Crl(crl) => crl::cmd(crl),
    }
}

#[derive(ValueEnum, Debug, Clone, PartialEq, Eq)]
pub enum Endorsement {
    /// Versioned Chip Endorsement Key
    Vcek,

    /// Versioned Loaded Endorsement Key
    Vlek,
}

impl fmt::Display for Endorsement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Endorsement::Vcek => write!(f, "VCEK"),
            Endorsement::Vlek => write!(f, "VLEK"),
        }
    }
}

impl FromStr for Endorsement {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "vcek" => Ok(Self::Vcek),
            "vlek" => Ok(Self::Vlek),
            _ => Err(anyhow::anyhow!("Endorsement type not found!")),
        }
    }
}
