# snphost

`snphost` is a Command Line Interface (CLI) utility designed for administrators managing AMD SEV-SNP enabled host systems. This tool facilitates interaction with the AMD SEV-SNP firmware device, enabling various operations such as certificate management and attestation processes.

- [Usage](#usage)
  - [1. help](#1-help)
  - [2. export](#2-export)
  - [3. import](#3-import)
  - [4. fetch ca](#4-fetch-ca)
  - [5. fetch vcek](#5-fetch-vcek)
  - [6. verify](#6-verify)
- [Building](#building)
  - [Ubuntu Dependencies](#ubuntu-dependencies)
  - [RHEL and Compatible Distributions Dependencies](#rhel-and-compatible-distributions-dependencies)
  - [openSUSE and Compatible Distributions Dependencies](#opensuse-and-compatible-distributions-dependencies)
- [Reporting Bugs](#reporting-bugs)

## Usage

### 1. help

Every `snphost` command and subcommand comes with a `--help` option that provides a description of its usage.

**Usage:**

```bash
snphost --help
```

or for a specific subcommand:

```bash
snphost <subcommand> --help
```

### 2. export

Exports the SEV-SNP certificate chain from the AMD Platform Security Processor (PSP) to a specified directory. The user must specify the desired encoding format (`der` or `pem`), the certificate file name, and the target directory path. This command is useful for retrieving the certificate chain for attestation purposes.

**Usage:**

```bash
snphost export [der|pem] CERT-FILE DIR-PATH
```

**Example:**

```bash
snphost export pem certificate.pem ./certs
```

### 3. import

Imports serialized SEV-SNP certificates to a specified certificate file. This certificate file can then be provided to QEMU to perform extended attestation on guests. Currently, only the ASK, ARK, VCEK, and VLEK certificates are supported for serialization.

**Usage:**

```bash
snphost import DIR-PATH CERT-FILE
```

**Example:**

```bash
snphost import ./certs certificate.pem
```

### 4. fetch 

Command to request certificates from the KDS.

**Usage:**

```bash
snphost fetch <SUBCOMMAND>
```

**Subcommands**

#### 1. ca 

Fetches the host system's Certificate Authority (CA) certificate chain and writes the encoded certificates to the specified directory. Users must specify the desired encoding format (`der` or `pem`).

**Usage:**

```bash
snphost fetch ca [der|pem] DIR-PATH
```

**Example:**

```bash
snphost fetch ca pem ./certs
```

#### 2. vcek

Fetches the host system's Versioned Chip Endorsement Key (VCEK) and writes the encoded certificate to the specified directory. Users must specify the desired encoding format (`der` or `pem`).

**Usage:**

```bash
snphost fetch vcek [der|pem] DIR-PATH
```

**Example:**

```bash
snphost fetch vcek pem ./certs
```

### 6. verify

Fetches certificates from the AMD PSP and verifies the certificate chain, ensuring its integrity and authenticity. This command is essential for validating the trustworthiness of the SEV-SNP environment.

**Usage:**

```bash
snphost verify
```

## Building

Some packages may need to be installed on the host system in order to build snpguest.

```bash
#Rust Installation
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
```

### Ubuntu Dependencies

```bash
sudo apt install build-essential
```

### RHEL and its compatible distributions Dependencies

```bash
sudo dnf groupinstall "Development Tools" "Development Libraries"
```

### openSUSE and its compatible distributions Dependencies

```bash
sudo zypper in -t pattern "devel_basis"
```

After installing the necessary dependencies, clone the `snphost` repository and build the project:

```bash
git clone https://github.com/virtee/snphost.git
cargo build --release
cd snphost/target/release
```

The compiled binary will be located in the `target/release` directory.

## Reporting Bugs

If you encounter any issues or bugs while using `snphost`, please report them by opening an issue by clicking [here](https://github.com/virtee/snphost/issues). Provide a detailed description of the problem, including steps to reproduce the issue and any relevant system information. This will help the maintainers address the problem more effectively.

---

*Note: This README is structured similarly to the [snpguest README](https://github.com/virtee/snpguest/blob/main/README.md) to maintain consistency across related projects.* 