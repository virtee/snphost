// SPDX-License-Identifier: Apache-2.0

#![deny(clippy::all)]

mod ok;

use std::{arch::x86_64, fs, path::PathBuf, result, str::FromStr};

use anyhow::{anyhow, bail, Context, Result};
use sev::firmware::host::*;
use structopt::StructOpt;

const VERSION: &str = env!("CARGO_PKG_VERSION");
const AUTHORS: &str = env!("CARGO_PKG_AUTHORS");

#[derive(StructOpt)]
struct SnpHost {
    #[structopt(subcommand)]
    pub cmd: SnpHostCmd,

    #[structopt(short, long, about = "Don't print anything to the console")]
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
    Ok,

    #[structopt(about = "Reset the SEV-SNP platform state")]
    Reset,

    #[structopt(about = "Verify a certificate chain")]
    Verify(verify::Verify),

    #[structopt(about = "Retrieve some content from the AMD Key Distribution Server (KDS)")]
    Fetch(fetch::Fetch),
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

fn ca_chain_url() -> Result<String> {
    Ok(format!(
        "https://kdsintf.amd.com/vcek/v1/{}/cert_chain",
        ProcessorGeneration::current()?.to_string()
    ))
}

fn crl_url() -> Result<String> {
    Ok(format!(
        "https://kdsintf.amd.com/vcek/v1/{}/crl",
        ProcessorGeneration::current()?.to_string()
    ))
}

fn vcek_url() -> Result<String> {
    let id = firmware()?
        .get_identifier()
        .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
        .context("error fetching identifier")?;
    let status = platform_status()?;
    let gen = ProcessorGeneration::current()?;

    Ok(format!("https://kdsintf.amd.com/vcek/v1/{}/{}?blSPL={:02}&teeSPL={:02}&snpSPL={:02}&ucodeSPL={:02}",
                         gen.to_string(), id, status.platform_tcb_version.bootloader,
                         status.platform_tcb_version.tee,
                         status.platform_tcb_version.snp,
                         status.platform_tcb_version.microcode))
}

#[derive(StructOpt)]
pub enum CertEncodingFormat {
    #[structopt(about = "Certificates are encoded in DER format")]
    Der,

    #[structopt(about = "Certificates are encoded in PEM format")]
    Pem,
}

impl ToString for CertEncodingFormat {
    fn to_string(&self) -> String {
        match self {
            Self::Der => "der".to_string(),
            Self::Pem => "pem".to_string(),
        }
    }
}

impl FromStr for CertEncodingFormat {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> result::Result<Self, Self::Err> {
        match s {
            "der" => Ok(Self::Der),
            "pem" => Ok(Self::Pem),
            _ => Err(anyhow!("unrecognized certificate encoding format")),
        }
    }
}

pub enum ProcessorGeneration {
    Milan,
    Genoa,
}

impl ProcessorGeneration {
    // Get the SEV generation of the processor currently running on the machine.
    // To do this, we execute a CPUID (label 0x80000001) and read the EAX
    // register as an array of bytes (each byte representing 8 bits of a 32-bit
    // value, thus the array is 4 bytes long). The formatting for these values is
    // as follows:
    //
    //  Base model:         bits 4:7
    //  Base family:        bits 8:11
    //  Extended model:     bits 16:19
    //  Extended family:    bits 20:27
    //
    // Extract the bit values from the array, and use them to calculate the MODEL
    // and FAMILY of the processor.
    //
    // The family calculation is as follows:
    //
    //      FAMILY = Base family + Extended family
    //
    // The model calculation is a follows:
    //
    //      MODEL = Base model | (Extended model << 4)
    //
    // Compare these values with the models and families of known processor generations to
    // determine which generation the current processor is a part of.
    fn current() -> Result<Self> {
        let cpuid = unsafe { x86_64::__cpuid(0x8000_0001) };
        let bytes: Vec<u8> = cpuid.eax.to_le_bytes().to_vec();

        let base_model = (bytes[0] & 0xF0) >> 4;
        let base_family = bytes[1] & 0x0F;

        let ext_model = bytes[2] & 0x0F;

        let ext_family = {
            let low = (bytes[2] & 0xF0) >> 4;
            let high = (bytes[3] & 0x0F) << 4;

            low | high
        };

        let model = (ext_model << 4) | base_model;
        let family = base_family + ext_family;

        let id = (model, family);

        let milan = (1, 25);
        let genoa = (17, 25);

        if id == milan {
            return Ok(Self::Milan);
        } else if id == genoa {
            return Ok(Self::Genoa);
        }

        Err(anyhow!("processor is not of a known SEV-SNP generation"))
    }
}

impl ToString for ProcessorGeneration {
    fn to_string(&self) -> String {
        let sstr = match self {
            Self::Milan => "Milan",
            Self::Genoa => "Genoa",
        };

        sstr.to_string()
    }
}

fn main() -> Result<()> {
    env_logger::init();

    let snphost = SnpHost::from_args();
    let result = match snphost.cmd {
        SnpHostCmd::Show(show) => show::cmd(show),
        SnpHostCmd::Export(export) => export::cmd(export),
        SnpHostCmd::Import(import) => import::cmd(import),
        SnpHostCmd::Ok => ok::cmd(snphost.quiet),
        SnpHostCmd::Reset => reset::cmd(),
        SnpHostCmd::Verify(verify) => verify::cmd(verify, snphost.quiet),
        SnpHostCmd::Fetch(fetch) => fetch::cmd(fetch),
    };

    if !snphost.quiet {
        if let Err(ref e) = result {
            eprintln!("ERROR: {}", e);
        }
    }

    result
}

mod show {
    use super::*;

    #[derive(StructOpt)]
    pub enum Show {
        #[structopt(about = "Show the current number of guests")]
        Guests,

        #[structopt(about = "Show the platform identifier")]
        Identifier,

        #[structopt(about = "Show the current platform and reported TCB version")]
        Tcb,

        #[structopt(about = "Show the VCEK DER download URL")]
        VcekUrl,

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
            Show::VcekUrl => {
                let url = vcek_url()?;

                println!("{}", url);
            }
            Show::Version => println!("{}", status.version),
        }

        Ok(())
    }
}

mod export {
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

        let entries = cert_entries()?;
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

            // Create the file for writing and open a file-handle.
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
            bail!(format!("path {} does not exist", import.path.display()));
        }

        let mut table: Vec<CertTableEntry> = vec![];

        for dir_entry in fs::read_dir(import.path.clone())? {
            match dir_entry {
                Ok(de) => table_add_entry(de, &mut table)?,
                Err(_) => {
                    bail!(format!(
                        "unable to read directory at path {}",
                        import.path.display()
                    ))
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

mod reset {
    use super::*;

    pub fn cmd() -> Result<()> {
        let mut fw = firmware()?;

        fw.snp_reset_config()
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))
            .context("error resetting SEV-SNP configuration")
    }
}

mod verify {
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
}

mod fetch {
    use super::*;

    #[derive(StructOpt)]
    pub enum Fetch {
        #[structopt(about = "Fetches the VCEK from the KDS")]
        Vcek(vcek::Vcek),

        #[structopt(about = "Fetches the CA from the KDS")]
        Ca(ca::Ca),

        #[structopt(about = "Fetches the CRL from the KDS")]
        Crl(crl::Crl),
    }

    pub fn cmd(fetch: Fetch) -> Result<()> {
        match fetch {
            Fetch::Vcek(vcek) => vcek::cmd(vcek),
            Fetch::Ca(ca) => ca::cmd(ca),
            Fetch::Crl(crl) => crl::cmd(crl),
        }
    }
}

mod crl {
    use super::*;
    use curl::easy::Easy;
    use std::{
        fs::{create_dir_all, OpenOptions},
        io::Write,
    };

    #[derive(StructOpt)]
    pub struct Crl {
        #[structopt(about = "The directory to write the CRL to")]
        pub dir_path: PathBuf,
    }

    pub fn cmd(crl: Crl) -> Result<()> {
        let url: String = crl_url()?;
        let bytes: Vec<u8> = fetch(&url)?;

        // Create Directory if not exists first, then write the files.
        if !crl.dir_path.exists() {
            create_dir_all(&crl.dir_path)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(crl.dir_path.join(format!(
                "{}.crl",
                ProcessorGeneration::current()?.to_string()
            )))?;

        file.write_all(&bytes)
            .context("Failed to write CRL to directory specified!")
    }

    pub fn fetch(url: &str) -> Result<Vec<u8>> {
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

        Ok(buf)
    }
}

mod ca {
    use super::*;
    use anyhow::{Context, Result};
    use curl::easy::Easy;
    use sev::certs::snp::{ca::Chain, Certificate};
    use std::{
        fs::{create_dir_all, OpenOptions},
        io::Write,
    };

    #[derive(StructOpt)]
    pub struct Ca {
        #[structopt(about = "The format the certs are encoded in (PEM or DER)")]
        pub encoding_fmt: CertEncodingFormat,

        #[structopt(about = "The directory to write the certificates to")]
        pub dir_path: PathBuf,
    }

    fn write_cert(path: &PathBuf, bytes: &[u8]) -> Result<()> {
        let mut file = OpenOptions::new().create(true).write(true).open(path)?;
        file.write_all(bytes)
            .context("Failed to write certificate!")
    }

    pub fn cmd(ca: Ca) -> Result<()> {
        let url: String = ca_chain_url()?;
        let cert_chain: Chain = fetch(&url)?;

        let ((ask_path, ask_bytes), (ark_path, ark_bytes)) = match ca.encoding_fmt {
            CertEncodingFormat::Der => (
                ("ask.der", cert_chain.ask.to_der()?),
                ("ark.der", cert_chain.ark.to_der()?),
            ),
            CertEncodingFormat::Pem => (
                ("ask.pem", cert_chain.ask.to_pem()?),
                ("ark.pem", cert_chain.ark.to_pem()?),
            ),
        };

        // Create Directory if not exists first, then write the files.
        if !ca.dir_path.exists() {
            create_dir_all(&ca.dir_path)?;
        }

        write_cert(&ca.dir_path.join(ask_path), &ask_bytes)?;
        write_cert(&ca.dir_path.join(ark_path), &ark_bytes)?;

        Ok(())
    }

    pub fn fetch(url: &str) -> Result<Chain> {
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

        Ok(Chain {
            ask: Certificate::from_pem(&buf[..2325])?,
            ark: Certificate::from_pem(&buf[2325..])?,
        })
    }
}

mod vcek {
    use super::*;

    use std::{
        fs::{create_dir_all, OpenOptions},
        io::Write,
    };

    use curl::easy::Easy;
    use sev::certs::snp::Certificate;

    #[derive(StructOpt)]
    pub struct Vcek {
        #[structopt(about = "The format in which to encode the certificate")]
        encoding_fmt: CertEncodingFormat,

        #[structopt(about = "The path of a directory to store the encoded VCEK in")]
        path: PathBuf,
    }

    pub fn cmd(vcek: Vcek) -> Result<()> {
        let url = vcek_url()?;
        let cert = fetch(&url).context(format!("unable to fetch VCEK from {}", url))?;

        let (vcek_name, vcek_bytes) = match vcek.encoding_fmt {
            CertEncodingFormat::Der => ("vcek.der", cert.to_der()?),
            CertEncodingFormat::Pem => ("vcek.pem", cert.to_pem()?),
        };

        // Create Directory if not exists first, then write the files.
        if !vcek.path.exists() {
            create_dir_all(&vcek.path)?;
        }

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .open(vcek.path.join(vcek_name))?;

        file.write_all(&vcek_bytes)?;

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
}
