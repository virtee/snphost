# snphost

`snphost` is a Command Line Interface (CLI) utility designed for administrators managing AMD SEV-SNP enabled host systems. This tool facilitates interaction with the AMD SEV-SNP firmware device, enabling various operations such as certificate management and attestation processes.

- [Usage](#usage)
  - [1. help](#1-help)
  - [2. export](#2-export)
  - [3. import](#3-import)
  - [4. ok](#4-ok)
  - [5. fetch](#5-fetch)
  - [6. show](#6-show)
  - [7. commit](#7-commit)
  - [8. config](#8-config)
  - [9. verify](#9-verify)
- [Building](#building)
  - [Ubuntu Dependencies](#ubuntu-dependencies)
  - [RHEL and Compatible Distributions Dependencies](#rhel-and-compatible-distributions-dependencies)
  - [openSUSE and Compatible Distributions Dependencies](#opensuse-and-compatible-distributions-dependencies)
- [Reporting Bugs](#reporting-bugs)

## Usage

### 1. `help`

Every `snphost` command and subcommand comes with a `--help` option that provides a description of its usage.

**Usage:**

```bash
snphost --help
```

or for a specific subcommand:

```bash
snphost <subcommand> --help
```

### 2. `export`

Deserializes a GHCB formatted cert chain file into individual certificates. The user must specify the desired encoding format (`der` or `pem`) for the certificates,  the file where the `GHCB` cert chain is stored in, and the target directory path where to store the deserialized certs. This command is useful for looking at the individual certs that will be used for an extended attestation.

**Usage:**

```bash
snphost export [der|pem] CERT-FILE DIR-PATH
```

**Example:**

```bash
snphost export pem ghcb-certs.bin ./certs
```

### 3. `import`

Converts a certificate chain into a GHCB formatted file for extended attestation. This formatted file can then be provided to QEMU to perform extended attestation on guests. Currently, only the `ASK`, `ASVK`, `ARK`, `VCEK`, and `VLEK` certificates are supported for serialization.

**Usage:**

```bash
snphost import DIR-PATH CERT-FILE
```

**Example:**

```bash
snphost import ./certs ghcb-certs.bin
```
### 4. `ok`

Verifies if the `snpost` service is operational.

**Usage:**

```sh
snphost ok
```

**Example:**

```
```

### 5. `fetch`

Command to request certificates from the KDS.

**Usage:**

```bash
snphost fetch <subcommand>
```

**Subcommands:**

#### 1. `ca` 

Fetches the host system's Certificate Authority (CA) certificate chain and writes the encoded certificates to the specified directory. Users must specify the desired encoding format (`der` or `pem`).

**Usage:**

```bash
snphost fetch ca [der|pem] DIR-PATH
```

**Example:**

```bash
snphost fetch ca pem ./certs
```

#### 2. `vcek`

Fetches the host system's Versioned Chip Endorsement Key (VCEK) and writes the encoded certificate to the specified directory. Users must specify the desired encoding format (`der` or `pem`).

**Usage:**

```bash
snphost fetch vcek [der|pem] DIR-PATH
```

**Example:**

```bash
snphost fetch vcek pem ./certs
```

#### 3. `crl`
Fetches the latest Certificate Revocation List (CRL) from the configured source.

```sh
snphost fetch crl
```

**Example:**

```bash
snphost fetch crl
```

### 6. `show`
Displays various SNP-related information.

**Usage:**
```sh
snphost show <subcommands>
```

**Subcommands:**

#### 1. `guests`
Lists all active guests.

**Usage:**
```sh
snphost show guests
```

#### 2. `identifier`
Displays the SNP identifier.

**Usage:**
```sh
snphost show identifier
```

#### 3. `tcb`
Shows the current Trusted Computing Base (TCB) version.

**Usage:**
```sh
snphost show tcb
```

#### 4. `vcek-url`
Displays the URL for fetching the VCEK certificate.

**Usage:**
```sh
snphost show vcek-url
```

#### 5. `version`

Prints the current version of `snphost`.

**Usage:**
```sh
snphost show version
```

### 7. `commit`
Commits pending configuration changes.

**Usage:**
```sh
snphost commit
```

### 8. `config`
Manages `snphost` configuration.

**Usage:**
```sh
snphost config <subcommand>
```

**Subcommands**

#### 1. `set`
Sets a configuration parameter.

**Usage:**
```sh
snphost config set BOOTLOADER TEE SNP-FW MICROCODE MASK-CHIP
```

**Example:**
```sh
snphost config set
```

#### 2.`reset`
Resets a configuration parameter to its default value.

**Usage:**
```sh
snphost config reset 
```

**Example:**
```sh
snphost config reset
```

### 9. `verify`

Reads the certificates in a directory and verifies the certificate chain, ensuring its integrity and authenticity. This command is essential for validating the trustworthiness of the certificates that can be then passed to complete attestation.

**Usage:**
```bash
snphost verify DIR-PATH
```

**Example:**
```bash
snphost verify ./certs
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