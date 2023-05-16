// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

mod ok;

use std::{fs, path::PathBuf};

use anyhow::{anyhow, Context, Result};
use sev::firmware::host::*;
use structopt::StructOpt;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[derive(StructOpt)]
struct SnpHost {
    #[structopt(subcommand)]
    pub cmd: SnpHostCmd,

    #[structopt(
        short = "q",
        long = "quiet",
        about = "Don't print anything to the console"
    )]
    pub quiet: bool,
}

#[allow(clippy::large_enum_variant)]
#[derive(StructOpt)]
#[structopt(author = AUTHORS, version = VERSION, about = "Utilities for managing the SEV-SNP environment")]
enum SnpHostCmd {
    #[structopt(about = "Display information about the SEV-SNP platform")]
    Show(show::Show),

    #[structopt(about = "Export a certificate chain to a given directory")]
    Export(export::Export),

    #[structopt(about = "Import a certificate chain to the AMD PSP")]
    Import(import::Import),

    #[structopt(about = "Probe system for SEV-SNP support")]
    Ok {
        #[structopt(subcommand)]
        gen: Option<ok::SevGeneration>,
    },
}

fn firmware() -> Result<Firmware> {
    Firmware::open().context("unable to open /dev/sev")
}

fn platform_status() -> Result<SnpPlatformStatus> {
    firmware()?
        .snp_platform_status()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to retrieve SNP platform status")
}

fn cert_entries() -> Result<Vec<CertTableEntry>> {
    let config = firmware()?
        .snp_get_ext_config()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("unable to retrieve SNP certificates")?;

    match config.certs {
        Some(c) => Ok(c),
        None => Err(anyhow!("no SNP certificates found")),
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let snphost = SnpHost::from_args();
    match snphost.cmd {
        SnpHostCmd::Show(show) => show::cmd(show),
        SnpHostCmd::Export(export) => export::cmd(export),
        SnpHostCmd::Import(import) => import::cmd(import),
        SnpHostCmd::Ok { gen } => ok::cmd(gen, snphost.quiet),
    }
}

mod show {
    use super::*;

    #[derive(StructOpt)]
    pub enum Generation {
        #[structopt(about = "Milan generation of SEV-SNP processors")]
        Milan,

        #[structopt(about = "Genoa generation of SEV-SNP processors")]
        Genoa,
    }

    impl ToString for Generation {
        fn to_string(&self) -> String {
            let s = match self {
                Self::Milan => "Milan",
                Self::Genoa => "Genoa",
            };

            s.to_string()
        }
    }

    #[derive(StructOpt)]
    pub enum Show {
        #[structopt(about = "Show the current number of guests")]
        Guests,

        #[structopt(about = "Show the platform identifier")]
        Identifier,

        #[structopt(about = "Show the current platform and reported TCB version")]
        Tcb,

        #[structopt(about = "Show the VCEK DER download URL")]
        VcekUrl(Generation),

        #[structopt(about = "Show the platform's firmware version")]
        Version,
    }

    pub fn cmd(show: Show) -> Result<()> {
        let status = platform_status()?;

        match show {
            Show::Guests => println!("{}", status.guest_count),
            Show::Identifier => {
                let id = firmware()?
                    .get_identifier()
                    .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
                    .context("error fetching identifier")?;

                println!("{}", id);
            }
            Show::Tcb => println!(
                "Reported TCB: {}\nPlatform TCB: {}",
                status.reported_tcb_version, status.platform_tcb_version
            ),
            Show::VcekUrl(gen) => {
                let id = firmware()?
                    .get_identifier()
                    .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
                    .context("error fetching identifier")?;
                let status = platform_status()?;

                println!("https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                         gen.to_string(), id, status.platform_tcb_version.bootloader,
                         status.platform_tcb_version.tee,
                         status.platform_tcb_version.snp,
                         status.platform_tcb_version.microcode);
            }
            Show::Version => println!("{}", status.version),
        }

        Ok(())
    }
}

mod export {
    use super::*;

    use std::{io::Write, result, str::FromStr};

    #[derive(StructOpt)]
    pub struct Export {
        #[structopt(about = "The encoding format the certs are encoded in (PEM or DER)")]
        pub encoding_fmt: CertEncodingFormat,

        #[structopt(about = "The directory to write the certificates to")]
        pub dir_path: PathBuf,
    }

    #[derive(StructOpt)]
    pub enum CertEncodingFormat {
        #[structopt(about = "Certificates are encoded in PEM format")]
        Pem,

        #[structopt(about = "Certificates are encoded in DER format")]
        Der,
    }

    impl ToString for CertEncodingFormat {
        fn to_string(&self) -> String {
            match self {
                Self::Pem => "pem".to_string(),
                Self::Der => "der".to_string(),
            }
        }
    }

    impl FromStr for CertEncodingFormat {
        type Err = anyhow::Error;

        fn from_str(s: &str) -> result::Result<Self, Self::Err> {
            match s {
                "pem" => Ok(Self::Pem),
                "der" => Ok(Self::Der),
                _ => Err(anyhow!("unrecognized certificate encoding format")),
            }
        }
    }

    pub fn cmd(export: Export) -> Result<()> {
        let (mut ark, mut ask, mut vcek) = (false, false, false);

        fs::create_dir_all(export.dir_path.clone()).context(format!(
            "unable to find or create directory {}",
            export.dir_path.display()
        ))?;

        let entries = cert_entries()?;
        for e in entries {
            let type_id = match e.cert_type {
                CertType::ARK => {
                    if ark {
                        return Err(anyhow!("multiple ARKs found"));
                    }
                    ark = true;

                    "ark"
                }
                CertType::ASK => {
                    if ask {
                        return Err(anyhow!("multiple ASKs found"));
                    }
                    ask = true;

                    "ask"
                }
                CertType::VCEK => {
                    if vcek {
                        return Err(anyhow!("multiple VCEKs found"));
                    }
                    vcek = true;

                    "vcek"
                }
                _ => continue,
            };

            let name = format!(
                "{}/{}.{}",
                export.dir_path.display(),
                type_id,
                export.encoding_fmt.to_string()
            );

            let mut file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .open(name.clone())?;

            file.write_all(&e.data)
                .context(format!("unable to cert data to file {}", name))?;
        }

        Ok(())
    }
}

mod import {
    use super::*;

    use std::fs::{read, DirEntry};

    #[derive(StructOpt)]
    pub struct Import {
        #[structopt(about = "The directory to find the encoded certificates")]
        pub path: PathBuf,
    }

    pub fn cmd(import: Import) -> Result<()> {
        if !import.path.exists() {
            return Err(anyhow!(format!(
                "path {} does not exist",
                import.path.display()
            )));
        }

        let mut table: Vec<CertTableEntry> = vec![];

        for dir_entry in fs::read_dir(import.path.clone())? {
            match dir_entry {
                Ok(de) => table_add_entry(de, &mut table)?,
                Err(_) => {
                    return Err(anyhow!(format!(
                        "unable to read directory at path {}",
                        import.path.display()
                    )))
                }
            }
        }

        firmware()?.snp_set_ext_config(ExtConfig::new_certs_only(table))?;

        Ok(())
    }

    fn table_add_entry(de: DirEntry, table: &mut Vec<CertTableEntry>) -> Result<()> {
        let cert_type = entry_get_type(&de.path())?;
        let data = read(de.path())?;

        table.push(CertTableEntry::new(cert_type, data));

        Ok(())
    }

    fn entry_get_type(path: &PathBuf) -> Result<CertType> {
        let file_name_string = path
            .file_name()
            .context(format!("unable to read file at path {:?}", path))?
            .to_string_lossy()
            .into_owned();

        let subs: Vec<&str> = file_name_string.split('.').collect();
        match subs[0] {
            "ark" => Ok(CertType::ARK),
            "ask" => Ok(CertType::ASK),
            "vcek" => Ok(CertType::VCEK),
            _ => Err(anyhow!(
                "unable to determine certificate type of path {:?}",
                path
            )),
        }
    }
}
