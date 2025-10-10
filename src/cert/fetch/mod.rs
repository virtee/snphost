// SPDX-License-Identifier: Apache-2.0

use super::*;

pub(crate) mod ca;
pub(crate) mod crl;
pub(crate) mod hashsticks;
pub(crate) mod vek;
use anyhow::Result;

#[derive(Subcommand)]
pub enum Fetch {
    /// Fetches the VCEK from the KDS
    Vek(vek::Vek),

    /// Fetches the CA from the KDS
    Ca(ca::Ca),

    /// Fetches the CRL from the KDS
    Crl(crl::Crl),

    /// Fetches the VLEK hashsticks from the KDS
    Hashsticks(hashsticks::Hashsticks),
}

pub fn cmd(fetch: Fetch) -> Result<()> {
    match fetch {
        Fetch::Vek(vek) => vek::cmd(vek),
        Fetch::Ca(ca) => ca::cmd(ca),
        Fetch::Crl(crl) => crl::cmd(crl),
        Fetch::Hashsticks(hashsticks) => hashsticks::cmd(hashsticks),
    }
}
