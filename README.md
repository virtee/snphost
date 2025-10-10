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
- [Common Workflows](#common-workflows)
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

Deserializes a GHCB formatted cert chain file into individual certificates. The user must specify the desired encoding format (`der` or `pem`) for the certificates, the file where the `GHCB` cert chain is stored in, and the target directory path where to store the deserialized certs. This command is useful for looking at the individual certs that will be used for an extended attestation.

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

Probes host system to confirm SEV-SNP support.

**Usage:**

```sh
snphost ok
```

### 5. `fetch`

Command to request certificates from the KDS.

**Usage:**

```bash
snphost fetch <subcommand>
```

**Subcommands:**

#### 1. `ca` 

Fetches the Certificate Authority (CA) chain corresponding to the host CPU generation and writes the encoded certificates to the specified directory. Users must specify the desired encoding format (`der` or `pem`). The `--endorser` argument specifies the type of endorsement certificate chain to pull, either VCEK or VLEK (Defaults to VCEK)

**Usage:**

```bash
snphost fetch ca [der|pem] DIR-PATH [--endorser vcek|vlek]
```

**Example:**

```bash
snphost fetch ca pem ./certs -e vcek
```

#### 2. `vek`

Fetches the Versioned Endorsement Key (VEK) corresponding to the host CPU generation and writes the encoded certificate to the specified directory. Users must specify the desired encoding format (`der` or `pem`). The URL of the VEK can be explicitly set. If not explicitly set, the URL will be generated based on firmware data.

**Usage:**

```bash
snphost fetch vek [der|pem] DIR-PATH [url] [--endorser vcek|vlek] [--client-cert <CERT-PATH>] [--private-key <KEY-PATH>]
```

**Example:**

```bash
snphost fetch vek pem ./certs --endorser vcek
```

#### 3. `crl`
Fetches the latest Certificate Revocation List (CRL) for the host CPU generation. The `--endorser` argument specifies the type of attestation signing key (defaults to VCEK).

```sh
snphost fetch crl DIR-PATH [--endorser vcek|vlek]
```

**Example:**

```bash
snphost fetch crl ./crl-dir -e vcek
```

#### 4. `hashsticks`
Fetches the VLEK hashsticks for the machines with identical host CPU generation and the reported TCB version as the host, then saves them to a file called "hashsticks". Users must specify the path to client certificate and the client private key. If there is no option specified, the command downloads and prepares the binary VLEK hashstick for the machine running this command. If option `--hwid ${hwid}` is specified, the command downloads and prepares the VLEK hashstick for the specified hwid. If option `--json /path/to/json` is specified, the command uses the provided file, which contains a list of hwid whose hashsticks will be fetched, as the request body to query KDS. Unlike no option or `--hwid ${hwid}` option, the whole response from the server will be saved. Users will need to process the response themselves. Option `--hwid` and `--json` are mutually exclusive. 

```sh
snphost fetch hashsticks DIR-PATH CERT-PATH KEY-PATH [--hwid <hwid>] [--json <hwid-json>]
```
A hwID JSON is needed for option `--json` should contain a JSON structure with an array of hwIDs, an example can be found below
```console
"hwids": [
    "29ea45c..b9a451",
    "46e2c6e..11364f",
]

```

**Example:**

```bash
snphost fetch hashsticks ./hashsticks-dir ./client-cert.pem ./client.key
```

### 6. `show`
Display information about the SEV-SNP platform.

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
Displays the unique CPU identifier.

**Usage:**
```sh
snphost show identifier
```

#### 3. `tcb`
Shows the current platform and reported Trusted Computing Base (TCB) version.

**Usage:**
```sh
snphost show tcb
```

#### 4. `vcek-url`
Displays the URL for fetching VCEK.

**Usage:**
```sh
snphost show vcek-url
```

#### 5. `vlek-url`
Displays the URL for fetching VLEK.

**Usage:**
```sh
snphost show vlek-url
```

#### 6. `hashsticks-url`
Displays the URL for fetching VLEK hashsticks.

**Usage:**
```sh
snphost show hashsticks-url
```

#### 7. `version`

Prints the platform's SEV-SNP firmware version`.

**Usage:**
```sh
snphost show version
```

### 7. `commit`
This command commits the current firmware and SNP platform config versions to the PSP.

**Note: This can't be undone and will not allow rollbacks to older versions.**

**Usage:**
```sh
snphost commit
```

### 8. `config`
Subcommands to manage the host machine's configuration.

**Usage:**
```sh
snphost config <subcommand>
```

**Subcommands**

#### 1. `set`
This command allows the user to change the config of the SNP platform. The user can provide the desired versions of the different TCB paramerters they would like to modify. The command will change the reported values by the PSP. In order to have this changes commited, the user would have to use snphost commit. The user can also provide a new mask-chip value that will change the mask chip bit field values in the config. 

**Usage:**
```sh
snphost config set BOOTLOADER TEE SNP-FW MICROCODE MASK-CHIP [FMC]
```

**Example:**
```sh
snphost config set 10 0 23 25 0
```

#### 2.`reset`
This command resets the SEV-SNP platform. This will clear all persistent data managed by the platform and reset the platform configuration to its last committed version.

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

Some packages may need to be installed on the host system in order to build snphost.

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

## Common Workflows

This section outlines common workflows for configuring and using `snphost` effectively on a host system with AMD SEV-SNP enabled.

### 1. Changing the SNP Configuration

To change the configuration of the SNP firmware, use the `config set` command followed by `commit`.

**Usage:**
```bash
snphost config set BOOTLOADER TEE SNP-FW MICROCODE MASK-CHIP
```
In Turin and higher generations use,
```bash
snphost config set BOOTLOADER TEE SNP-FW MICROCODE MASK-CHIP FMC
```

This command is used to configure the TCB parameters and the Mask Chip value for the AMD SEV-SNP platform. The configuration consists of two main parts: setting the TCB values and setting the Mask Chip value.

#### Part 1. TCB Parameters

BOOTLOADER, TEE, SNP-FW, MICROCODE, FMC (Optional and applicable only to Turin and newer chips.)
To view the current values of these fields, you can run:
```bash
snphost show tcb
```

**Example Output:**

```bash
Reported TCB: TCB Version:
  Microcode:   25
  SNP:         23
  TEE:         0
  Boot Loader: 10
  FMC:         None

Platform TCB: TCB Version:
  Microcode:   25
  SNP:         23
  TEE:         0
  Boot Loader: 10
  FMC:         None
```
With the config set command, you can change these values to an older version, but not to a newer version. Attempting to set a newer version will result in a failure.
Further, the config set command will change the Reported TCB. The Platform TCB will change only when you commit your changes.

#### Part 2. Mask Chip ID

The Mask Chip can be set to a value between 0 and 3, corresponding to its binary counterpart:
```bash
0 - 00
1 - 01
2 - 10
3 - 11
```
These values toggle the MASK-CHIP-KEY and MASK-CHIP-ID settings:

```bash
Bit 0: MASK-CHIP-ID
Bit 1: MASK-CHIP-KEY
```
For example, if you pass 2:

```bash
Bit 0 is 0, meaning MASK-CHIP-ID is disabled.
Bit 1 is 1, meaning MASK-CHIP-KEY is enabled.
```

To set the TCB parameters and Mask Chip, you can use the following command:

**Example:**
```bash
snphost config set 10 0 23 25 0
```

In this example,
```bash
10 is the Bootloader version.
0 is the TEE version.
23 is the SNP Firmware level.
25 is the Microcode level.
0 is the Mask Chip value which disables both mask chip id and mask chip key.
```
This command will update the values.

To commit these changes to firmware, you must use the snphost commit command by running:

```bash
snphost commit
```
*Note: Commit changes config permanently. You can't roll back to your previous version. Do Not commit values unless you are absolutely sure.*

---

### 2. Resetting Config Changes

To discard uncommitted configuration changes and revert to the last committed state:

```bash
snphost config reset
```

**Workflow:**

```bash
snphost config set 10 0 23 25 0
# decide to discard changes
snphost config reset
```

This is useful for reverting accidental or experimental changes before they are made permanent.

---

### 3. Extended Attestation Flow

*Note: This was the workflow used to set-up the host for extended attestation, this functionality is currently unavailable in upstream kernel, and it's subject to change*

This flow demonstrates fetching host certificates, verifying the certs, importing them into the correct gchb format, and passing them to QEMU for extended guest attestation.

```bash
# Fetch certificates from KDS
snphost fetch ca pem ./certs
snphost fetch vek pem ./certs

# Verify the certificate chain (optional but recommended)
snphost verify ./certs

# Serialize to GHCB format for QEMU
snphost import ./certs ghcb-certs.bin

# (Optional) To inspect GHCB-formatted file contents:
snphost export pem ghcb-certs.bin ./decoded-certs
```

**Use with QEMU:**

You can now pass `ghcb-certs.bin` to QEMU via the `sev-snp-certs` option:

```bash
qemu-system-x86_64 \
  ... \
  -object sev-snp-guest,id=sev0,sev-snp-certs=ghcb-certs.bin \
  ...
```

The certificates can now be retrieved in the guest using extended attestation.

## Reporting Bugs

If you encounter any issues or bugs while using `snphost`, please report them by opening an issue by clicking [here](https://github.com/virtee/snphost/issues). Provide a detailed description of the problem, including steps to reproduce the issue and any relevant system information. This will help the maintainers address the problem more effectively.

---

*Note: This README is structured similarly to the [snpguest README](https://github.com/virtee/snpguest/blob/main/README.md) to maintain consistency across related projects.*
