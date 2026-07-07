//! Timer value encodings, 4 bits each, ETSI EN 300 392-2 tables 28.112, 28.116, 28.122.

use std::time::Duration;

/// Ready timer (4 bits, table 28.112).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadyTimer(pub u8);

/// Standby timer (4 bits, table 28.122).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandbyTimer(pub u8);

/// Response wait timer (4 bits, table 28.116).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResponseWaitTimer(pub u8);

/// Shared ready/response-wait timer table.
fn ready_style_duration(code: u8) -> Duration {
    match code & 0x0F {
        0 => Duration::from_secs(0),
        1 => Duration::from_secs(1),
        2 => Duration::from_secs(2),
        3 => Duration::from_secs(4),
        4 => Duration::from_secs(5),
        5 => Duration::from_secs(6),
        6 => Duration::from_secs(8),
        7 => Duration::from_secs(9),
        8 => Duration::from_secs(10),
        9 => Duration::from_secs(20),
        10 => Duration::from_secs(30),
        11 => Duration::from_secs(60),
        12 => Duration::from_secs(120),
        13 => Duration::from_secs(300),
        14 => Duration::from_secs(600),
        _ => Duration::from_secs(1800),
    }
}

impl ReadyTimer {
    pub fn to_duration(&self) -> Duration {
        ready_style_duration(self.0)
    }
    pub fn into_raw(self) -> u64 {
        (self.0 & 0x0F) as u64
    }
}

impl ResponseWaitTimer {
    pub fn to_duration(&self) -> Duration {
        ready_style_duration(self.0)
    }
    pub fn into_raw(self) -> u64 {
        (self.0 & 0x0F) as u64
    }
}

impl StandbyTimer {
    pub fn to_duration(&self) -> Duration {
        match self.0 & 0x0F {
            0 => Duration::from_secs(0),
            1 => Duration::from_secs(60),
            2 => Duration::from_secs(300),
            3 => Duration::from_secs(1800),
            4 => Duration::from_secs(3600),
            5 => Duration::from_secs(600),
            6 => Duration::from_secs(7200),
            7 => Duration::from_secs(14400),
            8 => Duration::from_secs(28800),
            9 => Duration::from_secs(43200),
            10 => Duration::from_secs(86400),
            // NOTE: spec ambiguous for reserved values 11..15 — chosen behaviour: Duration::ZERO.
            _ => Duration::ZERO,
        }
    }
    pub fn into_raw(self) -> u64 {
        (self.0 & 0x0F) as u64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ready_timer_spot_checks() {
        assert_eq!(ReadyTimer(0).to_duration(), Duration::from_secs(0));
        assert_eq!(ReadyTimer(8).to_duration(), Duration::from_secs(10));
        assert_eq!(ReadyTimer(15).to_duration(), Duration::from_secs(1800));
    }

    #[test]
    fn response_wait_timer_spot_checks() {
        assert_eq!(ResponseWaitTimer(0).to_duration(), Duration::from_secs(0));
        assert_eq!(ResponseWaitTimer(11).to_duration(), Duration::from_secs(60));
        assert_eq!(ResponseWaitTimer(15).to_duration(), Duration::from_secs(1800));
    }

    #[test]
    fn standby_timer_spot_checks() {
        assert_eq!(StandbyTimer(0).to_duration(), Duration::from_secs(0));
        assert_eq!(StandbyTimer(5).to_duration(), Duration::from_secs(600));
        assert_eq!(StandbyTimer(15).to_duration(), Duration::ZERO);
    }
}
