// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::{fs::read, path::PathBuf};

use colorful::*;
use sev::certs::snp::{ca, Certificate, Chain, Verifiable};

#[derive(StructOpt)]
pub struct Verify {
    #[structopt(about = "The path to the ARK certificate")]
    ark: PathBuf,

    #[structopt(about = "The path to the ASK certificate")]
    ask: PathBuf,

    #[structopt(about = "The path to the VCEK certificate")]
    vcek: PathBuf,
}

pub fn cmd(verify: Verify, quiet: bool) -> Result<()> {
    let chain = chain(verify)?;

    let (ark, ask, vcek) = (
        (&chain.ca.ark, "ARK"),
        (&chain.ca.ask, "ASK"),
        (&chain.vcek, "VCEK"),
    );

    let mut err = true;

    if !quiet {
        println!("\n • = self signed, ⬑ = signs, •̷ = invalid self sign, ⬑̸ = invalid signs\n");
    }

    err |= status(ark, ark, true, quiet);
    err |= status(ark, ask, false, quiet);
    err |= status(ask, vcek, false, quiet);

    match err {
        true => Ok(()),
        false => Err(anyhow!("SEV-SNP/CA certificate verification failed")),
    }
}

fn status<'a, S>(
    signer: (&'a S, &str),
    signee: (&'a S, &str),
    self_signed: bool,
    quiet: bool,
) -> bool
where
    (&'a S, &'a S): Verifiable,
{
    let res = (signer.0, signee.0).verify().is_ok();

    if !quiet {
        println!("{}", ssym(res, self_signed, signer.1, signee.1));
    }

    res
}

fn ssym(res: bool, self_signed: bool, signer: &str, signee: &str) -> String {
    let sym = match (res, self_signed) {
        (true, true) => "•".green(),
        (true, false) => "⬑".green(),
        (false, true) => "•̷".red(),
        (false, false) => "⬑̸".red(),
    };

    match self_signed {
        true => format!("{} {}", signer, sym),
        false => format!("{} {} {}", signer, sym, signee),
    }
}

fn chain(verify: Verify) -> Result<Chain> {
    Ok(Chain {
        ca: ca::Chain {
            ark: cert(verify.ark, "ARK")?,
            ask: cert(verify.ask, "ASK")?,
        },
        vcek: cert(verify.vcek, "VCEK")?,
    })
}

fn cert(path: PathBuf, name: &str) -> Result<Certificate> {
    Certificate::from_pem(
        &read(path.clone()).context(format!("unable to read {}", path.display()))?,
    )
    .context(format!(
        "unable to parse {} certificate from {}",
        name,
        path.display()
    ))
}
