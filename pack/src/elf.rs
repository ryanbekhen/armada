//! checkELF: a program built for another architecture is refused, so a
//! pack can never carry a binary its machines cannot run.

const EM_X86_64: u16 = 62;
const EM_AARCH64: u16 = 183;

pub fn check(b: &[u8], arch: &str) -> Result<(), String> {
    if b.len() < 64 || &b[..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }
    let class = b[4];
    let little = match b[5] {
        1 => true,
        2 => false,
        d => return Err(format!("unknown ELF data encoding {d}")),
    };
    let machine = if little {
        u16::from_le_bytes([b[18], b[19]])
    } else {
        u16::from_be_bytes([b[18], b[19]])
    };
    let want = match arch {
        "amd64" => EM_X86_64,
        "arm64" => EM_AARCH64,
        _ => return Err(format!("unsupported architecture {arch:?}")),
    };
    if machine != want || class != 2 {
        let name = match machine {
            EM_X86_64 => "EM_X86_64".to_string(),
            EM_AARCH64 => "EM_AARCH64".to_string(),
            m => format!("machine {m}"),
        };
        return Err(format!("built for {name}, not {arch}"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(machine: u16) -> Vec<u8> {
        let mut b = vec![0u8; 64];
        b[..4].copy_from_slice(b"\x7fELF");
        b[4] = 2;
        b[5] = 1;
        b[18..20].copy_from_slice(&machine.to_le_bytes());
        b
    }

    #[test]
    fn checks_the_machine() {
        assert!(check(&header(EM_X86_64), "amd64").is_ok());
        assert!(check(&header(EM_AARCH64), "arm64").is_ok());
        assert_eq!(
            check(&header(EM_X86_64), "arm64").unwrap_err(),
            "built for EM_X86_64, not arm64"
        );
        assert!(check(b"#!/bin/sh\n", "amd64").is_err());
    }
}
