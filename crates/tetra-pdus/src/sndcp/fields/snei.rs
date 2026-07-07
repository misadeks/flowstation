//! Sub-Network Endpoint Identifier (SNEI), 16 bits.

use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

/// SNEI (16 bits).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Snei(pub u16);

impl Snei {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let raw = buffer.read_field(16, "snei")?;
        Ok(Snei(raw as u16))
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(self.0 as u64, 16);
        Ok(())
    }
}

impl core::fmt::Display for Snei {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Snei({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for v in [0u16, 1, 0xABCD, 0xFFFF] {
            let mut buf = BitBuffer::new_autoexpand(16);
            Snei(v).to_bitbuf(&mut buf).unwrap();
            buf.seek(0);
            assert_eq!(Snei::from_bitbuf(&mut buf).unwrap(), Snei(v));
        }
    }
}
