//! Errors produced by the `wap-gateway` crate.

use std::io;

/// Top-level error type for the WAP gateway.
#[derive(Debug, thiserror::Error)]
pub enum WapError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("failed to parse TOML: {0}")]
    Toml(#[from] toml::de::Error),

    #[error("WTP PDU decode error: {0}")]
    WtpDecode(String),

    #[error("WSP PDU decode error: {0}")]
    WspDecode(String),

    #[error("truncated PDU: expected {expected} bytes, got {actual}")]
    Truncated { expected: usize, actual: usize },
}

/// Convenience alias.
pub type WapResult<T> = std::result::Result<T, WapError>;
