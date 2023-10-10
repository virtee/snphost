// SPDX-License-Identifier: Apache-2.0

use super::*;

use cert::CertEncodingFormat;

use std::{fs::OpenOptions, io::Write};

use curl::easy::Easy;
use sev::certs::snp::Certificate;

#[derive(StructOpt)]
pub struct Vcek {
    #[structopt(about = "The format in which to encode the certificate")]
    encoding_fmt: CertEncodingFormat,

    #[structopt(about = "The path of a file to store the encoded VCEK")]
    path: PathBuf,
}

pub fn cmd(vcek: Vcek) -> Result<()> {
    let url = vcek_url()?;
    let cert = fetch(&url).context(format!("unable to fetch VCEK from {}", url))?;

    let bytes = match vcek.encoding_fmt {
        CertEncodingFormat::Der => cert.to_der()?,
        CertEncodingFormat::Pem => cert.to_pem()?,
    };

    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .open(vcek.path)?;
    file.write_all(&bytes)?;

    Ok(())
}

pub fn fetch(url: &str) -> Result<Certificate> {
    let mut handle = Easy::new();
    let mut buf: Vec<u8> = Vec::new();

    handle.url(url)?;
    handle.get(true)?;

    let mut transfer = handle.transfer();
    transfer.write_function(|data| {
        buf.extend_from_slice(data);
        Ok(data.len())
    })?;

    transfer.perform()?;
    drop(transfer);

    Ok(Certificate::from_der(buf.as_slice())?)
}
