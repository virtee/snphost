// SPDX-License-Identifier: Apache-2.0

use std::{fs::File, os::unix::io::AsRawFd};

use bitflags::bitflags;

use super::{SevGeneration, TestResult, TestState};

bitflags! {
    #[derive(Debug)]
    pub(super) struct VmsaFeatures: u64 {
        const SECURE_TSC = 1 << 9;
    }
}

pub(super) fn has_kvm_support() -> TestResult {
    let path = "/dev/kvm";

    let (stat, mesg) = match File::open(path) {
        Ok(kvm) => {
            let api_version = unsafe { libc::ioctl(kvm.as_raw_fd(), 0xAE00, 0) };
            if api_version < 0 {
                (
                    TestState::Fail,
                    "Error - accessing KVM device node failed".to_string(),
                )
            } else {
                (TestState::Pass, format!("API version: {}", api_version))
            }
        }
        Err(e) => (TestState::Fail, format!("Error reading {}: ({})", path, e)),
    };

    TestResult {
        name: "KVM supported".to_string(),
        stat,
        mesg: Some(mesg),
    }
}

pub(super) fn kvm_get_vmsa_features() -> Result<u64, String> {
    // _IOW(0xAE, 0xe2, struct kvm_device_attr) where struct is 24 bytes
    // https://docs.kernel.org/virt/kvm/api.html
    const KVM_GET_DEVICE_ATTR: u64 = 0x4018AEE2;
    const KVM_X86_GRP_SEV: u32 = 1;
    const KVM_X86_SEV_VMSA_FEATURES: u64 = 0;

    let kvm = File::open("/dev/kvm").map_err(|e| format!("unable to open /dev/kvm: {}", e))?;

    // Returns the kernel's sev_supported_vmsa_features bitmask.
    // https://docs.kernel.org/virt/kvm/x86/amd-memory-encryption.html
    // https://github.com/torvalds/linux/blob/master/arch/x86/include/uapi/asm/kvm.h
    #[repr(C)]
    struct KvmDeviceAttr {
        flags: u32,
        group: u32,
        attr: u64,
        addr: u64,
    }

    let mut val: u64 = 0;
    let attr = KvmDeviceAttr {
        flags: 0,
        group: KVM_X86_GRP_SEV,
        attr: KVM_X86_SEV_VMSA_FEATURES,
        addr: &mut val as *mut u64 as u64,
    };
    let r = unsafe { libc::ioctl(kvm.as_raw_fd(), KVM_GET_DEVICE_ATTR, &attr) };
    if r < 0 {
        return Err(format!(
            "KVM_GET_DEVICE_ATTR failed: {}",
            std::io::Error::last_os_error()
        ));
    }

    Ok(val)
}

pub(super) fn sev_enabled_in_kvm(gen: SevGeneration) -> TestResult {
    let path_loc = match gen {
        SevGeneration::Sev => "/sys/module/kvm_amd/parameters/sev",
        SevGeneration::Es => "/sys/module/kvm_amd/parameters/sev_es",
        SevGeneration::Snp => "/sys/module/kvm_amd/parameters/sev_snp",
    };
    let path = std::path::Path::new(path_loc);

    let (stat, mesg) = if path.exists() {
        match std::fs::read_to_string(path_loc) {
            Ok(result) => {
                if result.trim() == "1" || result.trim() == "Y" {
                    (TestState::Pass, None)
                } else {
                    (
                        TestState::Fail,
                        Some(format!(
                            "Error - contents read from {}: {}",
                            path_loc,
                            result.trim()
                        )),
                    )
                }
            }
            Err(e) => (
                TestState::Fail,
                Some(format!("Error - (unable to read {}): {}", path_loc, e,)),
            ),
        }
    } else {
        (
            TestState::Fail,
            Some(format!("Error - {} does not exist", path_loc)),
        )
    };

    TestResult {
        name: match gen {
            SevGeneration::Sev => "SEV enabled in KVM",
            SevGeneration::Es => "SEV-ES enabled in KVM",
            SevGeneration::Snp => "SEV-SNP enabled in KVM",
        }
        .to_string(),
        stat,
        mesg,
    }
}
