// SPDX-License-Identifier: Apache-2.0

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
