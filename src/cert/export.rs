// SPDX-License-Identifier: Apache-2.0

use super::*;
use anyhow::{bail, Context, Result};
use sev::{
    certs::snp::Certificate,
    firmware::host::{CertTableEntry, CertType},
};

use std::{
    fs::File,
    io::{BufReader, Read, Write},
    path::PathBuf,
};

// Convert kernel formatted certs into user readable certificates
fn cert_entries(cert_bytes: &mut [u8]) -> Result<Vec<CertTableEntry>> {
    let certs = CertTableEntry::vec_bytes_to_cert_table(cert_bytes)
        .context("Could not convert bytes to certs")?;
    Ok(certs)
}

#[derive(Parser)]
pub struct Export {
    /// The format the certs will be encoded in (PEM or DER)
    #[arg(value_name = "encoding", required = true)]
    pub encoding_fmt: EncodingFormat,

    /// File where the formatted certificates are stored.
    #[arg(value_name = "cert-file", required = true)]
    pub cert_file: PathBuf,

    /// The directory to write the certificates to
    #[arg(value_name = "dir-path", required = true)]
    pub dir_path: PathBuf,
}

pub fn cmd(export: Export) -> Result<()> {
    let (mut ark, mut ask, mut vcek, mut vlek) = (false, false, false, false);

    std::fs::create_dir_all(export.dir_path.clone()).context(format!(
        "unable to find or create directory {}",
        export.dir_path.display()
    ))?;

    // Read the cert file with the kenrel formatted certs
    let cert_file = File::open(export.cert_file)?;
    let mut reader = BufReader::new(cert_file);
    let mut cert_bytes = Vec::new();

    // Read file into vector.
    reader.read_to_end(&mut cert_bytes)?;

    // Create a vec of CertTableEntry (x509 versioned)
    let entries = cert_entries(&mut cert_bytes)?;

    for e in entries {
        let type_id = match e.cert_type {
            CertType::ARK => {
                if ark {
                    bail!("multiple ARKs found");
                }
                ark = true;

                "ark"
            }
            CertType::ASK => {
                if ask {
                    bail!("multiple ASKs found");
                }
                ask = true;

                "ask"
            }
            CertType::VLEK => {
                if vlek {
                    bail!("multiple VLEKs found");
                }
                vlek = true;

                "vlek"
            }
            CertType::VCEK => {
                if vcek {
                    bail!("multiple VCEKs found");
                }
                vcek = true;

                "vcek"
            }
            _ => continue,
        };

        let certificate = Certificate::from_bytes(&e.data)?;

        // Verify the certificate is in the requested format.
        let formatted_data: Vec<u8> = match export.encoding_fmt {
            EncodingFormat::Der => certificate.to_der()?,
            EncodingFormat::Pem => certificate.to_pem()?,
        };

        // Build out the expected name of the file.
        let name = format!(
            "{}/{}.{}",
            export.dir_path.display(),
            type_id,
            export.encoding_fmt
        );

        // Create the file for writing and open a file-handle.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(name.clone())?;

        // Write out the contents of the certificate to the file.
        file.write_all(&formatted_data)
            .context(format!("unable to cert data to file {}", name))?;
    }

    Ok(())
}
