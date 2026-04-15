# Troubleshooting Guide

# snphost ok - System Readiness Check Troubleshooting Guide

Quick reference for diagnosing and fixing `snphost ok` test failures.

## Prerequisites

- Must run on baremetal host (not inside a VM)
- Requires root/sudo privileges

## Summary of SEV Requirements

| Component | Minimum Version | Notes |
|-----------|----------------|-------|
| **Processor** | AMD EPYC 3rd Gen (Milan) | For full SEV-SNP support |
| **SEV Firmware** | 1.51+ | Check with `snphost show version` |
| **Linux Kernel** | 6.11+ | Or distro with SNP backport |
| **BIOS/AGESA** | Latest from vendor | SNP support varies by BIOS version |

## Common Quick Fixes

| Issue | Quick Fix |
|-------|-----------|
| Permission denied errors | Run with root `sudo snphost ok` |
| MSR read failed | `sudo modprobe msr` |
| `/dev/sev` not found | `sudo modprobe ccp` (PSP driver) |
| `/dev/kvm` errors | `sudo modprobe kvm && sudo modprobe kvm_amd` |

## Test Categories

| Technology | CPU Support | CPU Info | BIOS Configured | Platform Initialized | KVM Config | Compliance |
|------------|-------------|----------|----------------------|---------------------|------------|------------|
| **CPU & Platform** | [AMD Processor](#amd-processor)<br><br>[AMD EPYC Processor](#amd-epyc-processor) | [Physical Address Bits](#physical-address-bit-reduction)<br><br>[C-bit Position](#c-bit-position) | [Firmware Version](#firmware-version) | [/dev/sev Readable](#devsev-readable)<br><br>[/dev/sev Writable](#devsev-writable) | [KVM Support](#kvm-support) | [Memlock Limits](#memlock-limits) |
| **SME** | [SME Support](#sme-support) | | [SME Enabled](#sme-enabled) | | | |
| **SEV** | [SEV Support](#sev-support) | [Max Guests](#maximum-encrypted-guests)<br><br>[Page Flush MSR](#page-flush-msr-support) | [ASID Limits](#minimum-sev-only-asid) | [SEV Initialized](#sev-initialized) | [SEV Enabled in KVM](#sev-enabled-in-kvm) | |
| **SEV-ES** | [SEV-ES Support](#sev-es-support) | | | [SEV-ES Initialized](#sev-es-initialized) | [SEV-ES Enabled in KVM](#sev-es-enabled-in-kvm) | |
| **SEV-SNP** | [SEV-SNP Support](#sev-snp-support) | [VMPL Support](#vmpl-support--count) | [SNP Enabled](#snp-enabled)<br><br>[RMP Addresses](#rmp-addresses) | [SNP Initialized](#snp-initialized)<br><br>[RMP Initialized](#rmp-initialized) | [SEV-SNP Enabled in KVM](#sev-snp-enabled-in-kvm) | [Memory Alias Check](#memory-alias-check)<br><br>[TCB Comparison](#tcb-version-comparison) |

**Column Descriptions:**
- **CPU Support**: CPUID checks - does the processor have this feature?
- **CPU Info**: Informational CPUID values - configuration details and limits
- **BIOS Configured**: Check FW version & BIOS/UEFI settings
- **Platform Initialized**: Runtime state after kernel modules load and firmware initializes
- **KVM Config**: KVM module parameters and hypervisor readiness
- **Compliance**: Security validations and resource limits

---

## CPU Support

### AMD Processor

**Tests:** CPU vendor is AMD

**Requires:** AMD EPYC 7003 (Milan) or newer for SNP support (consumer Ryzen not supported)

---

### AMD EPYC Processor

**Tests:** Processor is EPYC server-class CPU

**Requires:** AMD EPYC 7003 (Milan) or newer for SNP support (consumer Ryzen not supported)

---

### SME Support

**Tests:** CPU has Secure Memory Encryption hardware support (CPUID 0x8000001F, EAX bit 0)

**Requires:** AMD EPYC 7001 (Naples) or newer, and at least AMD EPYC 7003 (Milan) for SNP support

---

### SEV Support

**Tests:** CPU has SEV hardware support (CPUID 0x8000001F, EAX bit 1)

**Requires:** AMD EPYC processor, and at least AMD EPYC 7003 (Milan) for SNP support

---

### SEV-ES Support

**Tests:** CPU has SEV-ES (Encrypted State) support (CPUID 0x8000001F, EAX bit 3)

**Requires:** AMD EPYC 7002 (Rome) or newer, and at least AMD EPYC 7003 (Milan) for SNP support

---

### SEV-SNP Support

**Tests:** CPU has SEV-SNP hardware support (CPUID 0x8000001F, EAX bit 4)

**Requires:** AMD EPYC 7003 (Milan) or newer

---

## CPU Info

### Physical Address Bit Reduction

**Tests:** Physical address bits lost when encryption enabled (informational)

**Typical Values:** 1 or 6, depending on generation

> **Example:** 52-bit physical addressing with reduction of 1 = 51 usable bits

---

### C-bit Position

**Tests:** Page table bit position indicating encrypted page (informational)

| Processor | C-bit Position |
|-----------|----------------|
| Milan     | 47 |
| Genoa/Turin | 51 |

---

### Maximum Encrypted Guests

**Tests:** Max simultaneous encrypted guests (informational)

| Processor | Max Guests |
|-----------|------------|
| Milan | 509 / 253 |
| Genoa/Turin | 1006 |

> **Note:** Actual count depends on ASID allocation (see BIOS "SEV-ES ASID Space Limit")

---

### Page Flush MSR Support

**Tests:** CPU supports Page Flush MSR optimization (informational, never fails)

**Status:**
- **ENABLED** (green): Optimization available
- **DISABLED** (yellow): Uses standard cache flushing (functional but slower)

> **Note:** If disabled but supported, check BIOS settings.

---

### VMPL Support / Count

**Tests:** VM Permission Levels supported (informational)

**Expected:** 4 VMPLs (VMPL0-VMPL3)

> **What are VMPLs?** Four privilege levels for guest software under SEV-SNP. Unexpected values may indicate engineering sample processor.

---

### Minimum SEV-only ASID

**Tests:** Minimum ASID for SEV-only guests (informational)

**Example:** If value is 500, then:
- ASIDs 1-499: SEV-ES/SEV-SNP guests
- ASIDs 500-1006: SEV-only guests

**Configuration:** BIOS → "SEV-ES ASID Space Limit"

---

## BIOS Configured

### Firmware Version

**Tests:** SEV firmware ≥ 1.51 (queries `/dev/sev` PLATFORM_STATUS)

> **⚠️ REQUIREMENT:** Firmware version **1.51 or higher** required for SEV-SNP support

**Test fails with "Invalid Firmware version: 0" (couldn't query /dev/sev):**
```bash
sudo snphost ok
lsmod | grep ccp  # Check if PSP driver loaded
sudo modprobe ccp  # Load PSP driver (creates /dev/sev)
```

**Test fails with firmware version < 1.51:**

Your firmware is too old for SNP support. Firmware can be upgraded either through a BIOS/UEFI bundled upgrade provided by the OEM vendor, or by using a standalone SEV firmware file (.sbin) from the [AMD SEV Developer Documentation](https://www.amd.com/en/developer/sev.html).

**To check Current Version:**
```bash
sudo snphost show version
```

> **Documentation References**
> - [AMD SEV-SNP Firmware ABI Specification](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/specifications/56860.pdf) - Section on firmware management
> - [Using SEV with AMD EPYC Processors](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/tuning-guides/58207-using-sev-with-amd-epyc-processors.pdf) - AMD Tuning Guide
> - Your system vendor's BIOS update documentation

---

### SME Enabled

**Tests:** SME is enabled via MSR 0xC0010010 (SYSCFG), bit 23

**Check:**
```bash
sudo snphost ok
sudo modprobe msr
```

**Enable in BIOS:**
1. Enter BIOS setup
2. Navigate to **CBS > CPU Common > SMEE**
3. Set to **Enabled**
4. Save and reboot

> **Details:** Reads Model-Specific Register (MSR) to check if Secure Memory Encryption is enabled at the system level. Requires the `msr` kernel module.

---

### SNP Enabled

**Tests:** SEV-SNP enabled via MSR 0xC0010010 (SYSCFG), bit 24

**Check:**
```bash
sudo snphost ok
sudo modprobe msr
```

**Enable in BIOS:**
1. Enter BIOS setup
2. **CBS > CPU Common > SNP Memory Coverage** > **Enabled**
3. **NBIO Common > SEV-SNP** > **Enabled**
4. Save and reboot
5. Verify: `dmesg | grep -i snp`

> **Details:** Checks if SNP is enabled at the platform level through the SYSCFG MSR.

---

### RMP Addresses

**Tests:** Reverse Map Table has valid base/end addresses (MSRs 0xC0010132, 0xC0010133)

**Enable in BIOS:**
1. Enter BIOS setup
2. **CBS > CPU Common > SNP Memory Coverage** → **Enabled**
3. Save and reboot
4. Verify: `dmesg | grep -i "RMP table"`

> **What is RMP?** System-wide data structure tracking memory ownership for SNP guests. Both base and end addresses must be non-zero.

---

## Platform Initialized

### /dev/sev Readable

**Tests:** `/dev/sev` device exists and readable

**Common Issues:**
| Issue | Fix |
|-------|-----|
| Permission denied | Run with `sudo snphost ok` |
| Device not found | See [Why /dev/sev Doesn't Exist](#why-devsev-doesnt-exist) for detailed troubleshooting |

**Quick Fix:**
```bash
# Load PSP driver (creates /dev/sev)
sudo modprobe ccp

# Run the test
sudo snphost ok
```

---

### /dev/sev Writable

**Tests:** `/dev/sev` writable (required for firmware commands)

**Common Issues:**
| Issue | Fix |
|-------|-----|
| Permission denied | Run with `sudo snphost ok` |
| Device not found | See [Why /dev/sev Doesn't Exist](#why-devsev-doesnt-exist) for detailed troubleshooting |
| SELinux/AppArmor blocking | Check security policy denials in system logs |

**Quick Fix:**
```bash
# Load PSP driver (creates /dev/sev)
sudo modprobe ccp

# Run the test with sudo
sudo snphost ok

# Verify device permissions
ls -la /dev/sev  # Should show: crw------- 1 root root
```

---

### SEV Initialized

**Tests:** SEV platform is in "Initialized" or "Working" state

**Fix:**

If `sudo snphost ok` fails on this test, try enabling SEV in KVM, then verify kernel logs:
```bash
sudo modprobe kvm_amd sev=1
dmesg | grep -i sev
```

> **Pass States:** "Initialized" (no guests running) or "Working" (guests active)

---

### SEV-ES Initialized

**Tests:** SEV-ES firmware initialized (platform status flags bit 8)

**Fix:**

If `sudo snphost ok` fails on this test, try enabling SEV in KVM, then verify kernel logs:
```bash
sudo modprobe kvm_amd sev=1 sev-es=1
dmesg | grep -i sev-es
cat /sys/module/kvm_amd/parameters/sev_es  # Should show Y or 1
```

---

### SNP Initialized

**Tests:** SNP firmware is in INIT state (SNP_PLATFORM_STATUS state field = 1)

**Fix:**

If `sudo snphost ok` fails on this test, try enabling SEV in KVM, then verify kernel logs:
```bash
uname -r  # Check kernel version (need 6.11+ or distro with SNP backport)
grep CONFIG_KVM_AMD_SEV /boot/config-$(uname -r)  # Must be y or m
sudo modprobe kvm_amd sev_snp=1
dmesg | grep -i sev-snp
```

> **KERNEL REQUIREMENT**
> - Linux **6.11+** mainline, OR
> - Distribution with SNP backport (Ubuntu 24.04+, RHEL 9.4+, etc.)
> - Kernel config: `CONFIG_KVM_AMD_SEV=y`

> **Note:** Also requires BIOS to allocate RMP memory (SNP Memory Coverage enabled)

---

### RMP Initialized

**Tests:** RMP table initialized by SNP firmware (IS_RMP_INIT bit)

**Verify:**
```bash
grep CONFIG_KVM_AMD_SEV /boot/config-$(uname -r)  # Must be y
dmesg | grep -E "RMP|SNP|SEV"
```

**Fix:** Reboot if firmware was recently updated

---

## KVM Config

### KVM Support

**Tests:** KVM hypervisor available and functional (opens `/dev/kvm`, queries API)

**Check:**
```bash
sudo snphost ok
sudo modprobe kvm && sudo modprobe kvm_amd
ls -la /dev/kvm
dmesg | grep -i kvm
```

**Check Kernel Configuration:**
```bash
# Check if KVM modules are available
grep -E "CONFIG_KVM|CONFIG_KVM_AMD" /boot/config-$(uname -r)

# Should show:
# CONFIG_KVM=y (or =m)
# CONFIG_KVM_AMD=y (or =m)
```

**Enable in BIOS:**
1. Enable **SVM (Secure Virtual Machine)** in BIOS
2. Typically under **CBS > CPU Common > SVM Mode** or **Advanced > CPU Configuration**
3. Save and reboot

> **Kernel Requirements:**
> - `CONFIG_KVM=y` or `=m`
> - `CONFIG_KVM_AMD=y` or `=m`
> - If missing, kernel recompile or distro upgrade needed

---

### SEV Enabled in KVM

**Tests:** `kvm_amd` module has SEV support enabled

**Check:**
```bash
cat /sys/module/kvm_amd/parameters/sev  # Should show Y or 1
```

**Enable:**
```bash
# Temporary
sudo modprobe -r kvm_amd && sudo modprobe kvm_amd sev=1

# Persistent
echo "options kvm_amd sev=1 sev-es=1 sev-snp=1" | sudo tee /etc/modprobe.d/kvm.conf
sudo modprobe -r kvm_amd && sudo modprobe kvm_amd
```

---

### SEV-ES Enabled in KVM

**Tests:** `kvm_amd` module has SEV-ES support enabled

**Enable:** Same as [SEV Enabled in KVM](#sev-enabled-in-kvm), ensure `sev-es=1` parameter

---

### SEV-SNP Enabled in KVM

**Tests:** `kvm_amd` module has SEV-SNP support enabled

**Check:**
```bash
cat /sys/module/kvm_amd/parameters/sev_snp  # Should show Y or 1
```

**Check SNP Support:**
```bash
# Check kernel version
uname -r  # Need 6.11+ or distro with backport

# Check if sev_snp parameter exists
ls /sys/module/kvm_amd/parameters/sev_snp

# Check kernel config
grep CONFIG_KVM_AMD_SEV /boot/config-$(uname -r)  # Must be 'y'
```

**Enable:**
```bash
# Persistent configuration
echo "options kvm_amd sev=1 sev-es=1 sev-snp=1" | sudo tee /etc/modprobe.d/kvm.conf
sudo modprobe -r kvm_amd && sudo modprobe kvm_amd
```

> **If parameter file doesn't exist:** Kernel lacks SNP support - upgrade kernel or use supported distro.

---

## Compliance

### Memlock Limits

**Tests:** `RLIMIT_MEMLOCK` soft and hard limits (informational)

**Why It Matters:** SEV-SNP guests require entire memory pinned in RAM. Low memlock limit causes guest launch failures.

**Recommended Configuration:**

```bash
# For user sessions
echo "* - memlock unlimited" | sudo tee -a /etc/security/limits.conf

# For systemd services (e.g., libvirtd)
# Add to service unit:
[Service]
LimitMEMLOCK=infinity
```

**Verify:** `ulimit -l`

**Guideline:** memlock ≥ (total guest RAM) + (256 MiB per guest overhead)

---

### Memory Alias Check

**Tests:** Memory aliasing detection completed, no aliasing detected (security mitigation for CVE-2024-21944)

**Update Required:**
1. Update SEV firmware to latest version
2. Update BIOS/AGESA per [AMD-SB-3015](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3015.html)
3. Reboot (check runs during SNP init)

> **Security Advisory:** Addresses CVE-2024-21944 (AMD-SB-3015). Alias check runs during SNP initialization.

---

### TCB Version Comparison

**Tests:** Platform TCB matches Reported TCB (both from SNP_PLATFORM_STATUS)

**Check:**
```bash
sudo snphost ok
```

**Fix mismatch:**

```bash
# Option 1: Commit current TCB (irreversible, prevents rollback)
sudo snphost commit

# Option 2: Set reported TCB to match platform
sudo snphost config set-reported-tcb
```

> **⚠️ WARNING**
> `snphost commit` is **irreversible** - it permanently prevents rollback to older firmware/microcode versions.

**TCB Components:**
| Component | Description |
|-----------|-------------|
| Microcode | CPU microcode version |
| SNP | SNP firmware security version |
| TEE | Trusted Execution Environment version |
| Boot Loader | PSP bootloader security version |
| FMC | Firmware Management Component (Turin+ only; None on older systems) |

**Expected Mismatch:** If you intentionally set lower Reported TCB for backwards compatibility.

---

## Why /dev/sev Doesn't Exist

If `/dev/sev` is missing, multiple tests will fail (firmware version, SEV/SNP initialized, TCB comparison, etc.). Use this table to identify and fix the root cause:

| Cause | How to Detect | Fix |
|-------|---------------|-----|
| **CCP kernel module not loaded** | `lsmod \| grep ccp` shows nothing | `sudo modprobe ccp` |
| **Running inside a VM** | `systemd-detect-virt` returns something other than "none" | Must run on baremetal host |
| **Kernel missing CCP/PSP config** | `grep CONFIG_CRYPTO_DEV_CCP /boot/config-$(uname -r)` is missing or `=n` | Upgrade kernel or recompile with CCP support |
| **SEV disabled in BIOS** | PSP won't initialize SEV subsystem | Enable SEV in BIOS (CBS > CPU Common) |
| **IOMMU not enabled** | SEV requires IOMMU | Enable IOMMU in BIOS; ensure `iommu=pt` kernel param |
| **PSP firmware issue** | `dmesg \| grep -i psp` shows errors | Update BIOS (PSP firmware is bundled with BIOS) |
| **Kernel boot params missing** | `cat /proc/cmdline` | May need `mem_encrypt=on` on older kernels |
| **Kernel too old** | `uname -r` | Need 4.16+ for basic SEV, 6.11+ for SNP |

**Quick diagnostic:**
```bash
# 1. Check if running on baremetal
systemd-detect-virt               # Must output "none"

# 2. Check if CCP module is loaded
lsmod | grep ccp

# 3. Load CCP module if missing
sudo modprobe ccp

# 4. Check kernel configuration
grep -E "CONFIG_CRYPTO_DEV_CCP|CONFIG_KVM_AMD_SEV" /boot/config-$(uname -r)

# 5. Check for PSP/CCP driver errors
dmesg | grep -iE "ccp|psp|sev"
```

> **Note:** If `/dev/sev` exists but tests still fail with "unable to open /dev/sev", the issue is file permissions — run with `sudo`.

---

## BIOS Configuration Reference

Required BIOS/UEFI settings for SEV-SNP (paths vary by OEM):

| Setting | Location | Value | Purpose |
|---------|----------|-------|---------|
| **SMEE** | CBS > CPU Common | Enabled | Enable memory encryption |
| **SNP Memory Coverage** | CBS > CPU Common | Enabled | Allocate RMP memory |
| **SEV-SNP** | NBIO Common | Enabled | Enable SNP feature |
| **SVM** | CBS > CPU Common | Enabled | Enable virtualization |
| **IOMMU** | NBIO Common | Enabled | I/O memory management |
| **SEV-ES ASID Space Limit Control** | CBS > CPU Common | Manual | Control ASID allocation |
| **SEV-ES ASID Space Limit** | CBS > CPU Common | Custom | Split ASIDs between SEV-only and SEV-ES/SNP |

---

## Additional Resources

### AMD Official Documentation
- [SEV-SNP Firmware ABI Specification](https://docs.amd.com/api/khub/documents/x_tYkgJNtfpvwPq45NrSQ/content)
- [AMD SEV Developer Resources](https://www.amd.com/en/developer/sev.html)
- [Using SEV with AMD EPYC Processors - Tuning Guide](https://www.amd.com/content/dam/amd/en/documents/epyc-technical-docs/tuning-guides/58207-using-sev-with-amd-epyc-processors.pdf)

### Linux Kernel Documentation
- [AMD Memory Encryption Documentation](https://docs.kernel.org/arch/x86/amd-memory-encryption.html)
- [KVM AMD Memory Encryption](https://docs.kernel.org/virt/kvm/x86/amd-memory-encryption.html)

### Community Resources
- [AMDESE/AMDSEV GitHub Repository](https://github.com/AMDESE/AMDSEV)
- [Ubuntu: Confidential Computing with AMD](https://documentation.ubuntu.com/server/how-to/virtualisation/sev-snp/)
- [libvirt: Launch Security with AMD SEV](https://libvirt.org/kbase/launch_security_sev.html)

### Security Advisories
- [AMD Security Bulletin AMD-SB-3015](https://www.amd.com/en/resources/product-security/bulletin/amd-sb-3015.html) - Memory alias check (CVE-2024-21944)
