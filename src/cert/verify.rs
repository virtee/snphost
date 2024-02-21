// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use std::{
    fs::read,
    path::{Path, PathBuf},
};

use colorful::*;
use sev::certs::snp::{ca, Certificate, Chain, Verifiable};
use structopt::StructOpt;

pub fn find_cert_in_dir(dir: &Path, cert: &str) -> Result<PathBuf, anyhow::Error> {
    if dir.join(format!("{cert}.pem")).exists() {
        Ok(dir.join(format!("{cert}.pem")))
    } else if dir.join(format!("{cert}.der")).exists() {
        Ok(dir.join(format!("{cert}.der")))
    } else {
        return Err(anyhow::anyhow!("{cert} certificate not found in directory"));
    }
}

#[derive(StructOpt)]
pub struct Verify {
    #[structopt(help = "Path to directory containing certificates.")]
    pub certs_dir: PathBuf,
}

pub fn cmd(verify: Verify, quiet: bool) -> Result<()> {
    let ark_path = find_cert_in_dir(&verify.certs_dir, "ark")?;
    let ask_path = find_cert_in_dir(&verify.certs_dir, "ask")?;
    let mut vek_type: &str = "VCEK";
    let vek_path = match find_cert_in_dir(&verify.certs_dir, "vlek") {
        Ok(vlek_path) => {
            vek_type = "VLEK";
            vlek_path
        }
        Err(_) => find_cert_in_dir(&verify.certs_dir, "vcek")?,
    };

    // Get a cert chain from directory
    let cert_chain = chain(ark_path, ask_path, vek_path, vek_type)?;

    let ark = (&cert_chain.ca.ark, "ARK");
    let ask = (&cert_chain.ca.ask, "ASK");
    let vek = (&cert_chain.vek, vek_type);

    let mut err = true;

    if !quiet {
        println!("\n • = self signed, ⬑ = signs, •̷ = invalid self sign, ⬑̸ = invalid signs\n");
    }

    err |= status(ark, ark, true, quiet);
    err |= status(ark, ask, false, quiet);
    err |= status(ask, vek, false, quiet);

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

fn chain(ark_path: PathBuf, ask_path: PathBuf, vek_path: PathBuf, vek_type: &str) -> Result<Chain> {
    Ok(Chain {
        ca: ca::Chain {
            ark: cert(ark_path, "ARK")?,
            ask: cert(ask_path, "ASK")?,
        },
        vek: cert(vek_path, vek_type)?,
    })
}

fn cert(path: PathBuf, name: &str) -> Result<Certificate> {
    Certificate::from_bytes(
        &read(path.clone()).context(format!("unable to read {}", path.display()))?,
    )
    .context(format!(
        "unable to parse {} certificate from {}",
        name,
        path.display()
    ))
}
