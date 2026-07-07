//! QoS field (12 bits). Not yet consumed by any PDU; provided for completeness.

use tetra_core::{BitBuffer, pdu_parse_error::PduParseErr};

/// Quality of Service parameters (12 bits total).
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Qos {
    /// 1 bit
    pub multi_slot_flag: u8,
    /// 3 bits
    pub rag: u8,
    /// 2 bits
    pub channel_width: u8,
    /// 1 bit
    pub mac_block_type: u8,
    /// 1 bit
    pub dssl: u8,
    /// 2 bits
    pub max_encoding: u8,
    /// 2 bits
    pub bandwidth: u8,
}

#[allow(dead_code)]
impl Qos {
    pub fn from_bitbuf(buffer: &mut BitBuffer) -> Result<Self, PduParseErr> {
        let multi_slot_flag = buffer.read_field(1, "multi_slot_flag")? as u8;
        let rag = buffer.read_field(3, "rag")? as u8;
        let channel_width = buffer.read_field(2, "channel_width")? as u8;
        let mac_block_type = buffer.read_field(1, "mac_block_type")? as u8;
        let dssl = buffer.read_field(1, "dssl")? as u8;
        let max_encoding = buffer.read_field(2, "max_encoding")? as u8;
        let bandwidth = buffer.read_field(2, "bandwidth")? as u8;
        Ok(Qos {
            multi_slot_flag,
            rag,
            channel_width,
            mac_block_type,
            dssl,
            max_encoding,
            bandwidth,
        })
    }

    pub fn to_bitbuf(&self, buffer: &mut BitBuffer) -> Result<(), PduParseErr> {
        buffer.write_bits(self.multi_slot_flag as u64, 1);
        buffer.write_bits(self.rag as u64, 3);
        buffer.write_bits(self.channel_width as u64, 2);
        buffer.write_bits(self.mac_block_type as u64, 1);
        buffer.write_bits(self.dssl as u64, 1);
        buffer.write_bits(self.max_encoding as u64, 2);
        buffer.write_bits(self.bandwidth as u64, 2);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let qos = Qos {
            multi_slot_flag: 1,
            rag: 5,
            channel_width: 2,
            mac_block_type: 1,
            dssl: 0,
            max_encoding: 3,
            bandwidth: 2,
        };
        let mut buf = BitBuffer::new_autoexpand(16);
        qos.to_bitbuf(&mut buf).unwrap();
        assert_eq!(buf.get_pos(), 12);
        buf.seek(0);
        assert_eq!(Qos::from_bitbuf(&mut buf).unwrap(), qos);
    }
}
