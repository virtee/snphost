// SPDX-License-Identifier: Apache-2.0

use cert::CertEncodingFormat;
use sev::certs::snp::Certificate;

use super::*;

use std::io::Write;

fn identify_cert(buf: &[u8]) -> CertEncodingFormat {
    const PEM_START: &[u8] = b"-----BEGIN CERTIFICATE-----";
    match buf {
        PEM_START => CertEncodingFormat::Pem,
        _ => CertEncodingFormat::Der,
    }
}

#[derive(StructOpt)]
pub struct Export {
    #[structopt(about = "The format the certs are encoded in (PEM or DER)")]
    pub encoding_fmt: CertEncodingFormat,

    #[structopt(about = "The directory to write the certificates to")]
    pub dir_path: PathBuf,
}

pub fn cmd(export: Export) -> Result<()> {
    let (mut ark, mut ask, mut vcek) = (false, false, false);

    fs::create_dir_all(export.dir_path.clone()).context(format!(
        "unable to find or create directory {}",
        export.dir_path.display()
    ))?;

    let entries: Vec<CertTableEntry> = cert_entries()?;
    for e in entries {
        let type_id: &str = match e.cert_type {
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
            CertType::VCEK => {
                if vcek {
                    bail!("multiple VCEKs found");
                }
                vcek = true;

                "vcek"
            }
            _ => continue,
        };

        // Attempt to identify the current format of the certificate in
        // hypervisor memory and build a Certificate from it.
        let certificate: Certificate = match identify_cert(&e.data[..27]) {
            CertEncodingFormat::Der => Certificate::from_der(&e.data)?,
            CertEncodingFormat::Pem => Certificate::from_pem(&e.data)?,
        };

        // Verify the certificate is in the requested format.
        let formatted_data: Vec<u8> = match export.encoding_fmt {
            CertEncodingFormat::Der => certificate.to_der()?,
            CertEncodingFormat::Pem => certificate.to_pem()?,
        };

        // Build out the expected name of the file.
        let name = format!(
            "{}/{}.{}",
            export.dir_path.display(),
            type_id,
            export.encoding_fmt.to_string()
        );

        // Create the file for writing.
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .open(name.clone())?;

        // Write out the contents of the certificate to the file.
        file.write_all(&formatted_data)
            .context(format!("unable to cert data to file {}", name))?;
    }
    Ok(())
}
