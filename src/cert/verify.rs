// SPDX-License-Identifier: Apache-2.0

use super::*;

use anyhow::{anyhow, Context, Result};
use std::{
    fs::read,
    path::{Path, PathBuf},
};

use colorful::*;
use sev::certs::snp::{ca, Certificate, Chain, Verifiable};

#[derive(Subcommand)]
pub enum Verify {
    /// Verify the certificate chain.
    Certs(certificate_chain::Args),

    /// Verify the VLEK hashstick.
    VlekHashstick(vlek_hashstick::Args),
}

pub fn cmd(verify: Verify, quiet: bool) -> Result<()> {
    match verify {
        Verify::Certs(args) => certificate_chain::cmd(args, quiet),
        Verify::VlekHashstick(args) => vlek_hashstick::cmd(args, quiet),
    }
}

pub fn find_cert_in_dir(dir: &Path, cert: &str) -> Result<PathBuf, anyhow::Error> {
    if dir.join(format!("{cert}.pem")).exists() {
        Ok(dir.join(format!("{cert}.pem")))
    } else if dir.join(format!("{cert}.der")).exists() {
        Ok(dir.join(format!("{cert}.der")))
    } else {
        Err(anyhow::anyhow!("{cert} certificate not found in directory"))
    }
}
mod certificate_chain {

    use super::*;

    #[derive(Parser)]
    pub struct Args {
        /// Path to directory containing certificates.
        #[arg(value_name = "dir-path", required = true)]
        pub dir_path: PathBuf,
    }

    pub fn cmd(verify: Args, quiet: bool) -> Result<()> {
        let ark_path = find_cert_in_dir(&verify.dir_path, "ark")?;
        let (mut vek_type, mut sign_type): (&str, &str) = ("vcek", "ask");
        let (vek_path, ask_path) = match find_cert_in_dir(&verify.dir_path, "vlek") {
            Ok(vlek_path) => {
                (vek_type, sign_type) = ("vlek", "asvk");
                (vlek_path, find_cert_in_dir(&verify.dir_path, sign_type)?)
            }
            Err(_) => (
                find_cert_in_dir(&verify.dir_path, vek_type)?,
                find_cert_in_dir(&verify.dir_path, sign_type)?,
            ),
        };

        // Get a cert chain from directory
        let cert_chain = chain(ark_path, ask_path, vek_path, vek_type, sign_type)?;

        let ark = (&cert_chain.ca.ark, "ARK");
        let ask = (&cert_chain.ca.ask, sign_type);
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

    fn chain(
        ark_path: PathBuf,
        ask_path: PathBuf,
        vek_path: PathBuf,
        vek_type: &str,
        sign_type: &str,
    ) -> Result<Chain> {
        Ok(Chain {
            ca: ca::Chain {
                ark: cert(ark_path, "ARK")?,
                ask: cert(ask_path, sign_type)?,
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
}

mod vlek_hashstick {
    use super::*;
    use sev::{firmware::host::WrappedVlekHashstick, parser::ByteParser, Generation};

    #[derive(Parser)]
    pub struct Args {
        /// Path to the VLEK hashstick file.
        #[arg(value_name = "hashstick-file", required = true)]
        pub hashstick_file: PathBuf,
    }

    pub fn cmd(args: Args, quiet: bool) -> Result<()> {
        if !args.hashstick_file.exists() {
            return Err(anyhow::anyhow!(
                "path {} does not exist",
                args.hashstick_file.display()
            ));
        }

        let hashstick_bytes =
            read(&args.hashstick_file).context("Failed to read VLEK hashshtick file")?;

        let generation = Generation::identify_host_generation()?;

        let hashstick = WrappedVlekHashstick::from_bytes_with(&hashstick_bytes, generation)
            .context("Failed to parse VLEK hashshtick")?;

        // Verify the VLEK hashstick
        let reported_tcb = snp_platform_status()?.reported_tcb_version;

        if hashstick.tcb_version != reported_tcb {
            return Err(anyhow::anyhow!(
                "VLEK hashstick TCB version:\n {} \ndoes not match reported TCB version:\n {}",
                hashstick.tcb_version,
                reported_tcb
            ));
        } else if !quiet {
            println!(
                "VLEK hashstick TCB version:\n {} \nmatches reported TCB version:\n {}",
                hashstick.tcb_version, reported_tcb
            );
        }

        Ok(())
    }
}
