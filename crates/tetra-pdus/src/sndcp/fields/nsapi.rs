//! Network Service Access Point Identifier (NSAPI), 4 bits.

use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

/// NSAPI (4 bits, valid values 0..=15).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Nsapi(pub u8);

impl Nsapi {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let raw = buffer.read_field(4, "nsapi")?;
        Nsapi::try_from(raw as u8).map_err(|_| PduParseErr::InvalidValue { field: "nsapi", value: raw })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(self.0 as u64, 4);
        Ok(())
    }
}

impl std::convert::TryFrom<u8> for Nsapi {
    type Error = ();
    fn try_from(x: u8) -> Result<Self, Self::Error> {
        if x <= 15 { Ok(Nsapi(x)) } else { Err(()) }
    }
}

impl core::fmt::Display for Nsapi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Nsapi({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for v in 0u8..=15 {
            let mut buf = BitBuffer::new_autoexpand(8);
            Nsapi(v).to_bitbuf(&mut buf).unwrap();
            buf.seek(0);
            assert_eq!(Nsapi::from_bitbuf(&mut buf).unwrap(), Nsapi(v));
        }
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(Nsapi::try_from(16).is_err());
    }
}
