use thiserror::Error;

/// Core error type used by protocol and parser code.
#[derive(Debug, Error)]
pub enum Error {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("invalid high-entropy secret")]
    InvalidSecret,
    #[error("frame length {length} exceeds maximum {max}")]
    FrameTooLarge { length: usize, max: usize },
    #[error("unknown frame type: {0:#04x}")]
    UnknownFrameType(u8),
    #[error("malformed frame: {0}")]
    MalformedFrame(&'static str),
    #[error("authentication failed")]
    Auth,
    #[error("noise runtime error: {0}")]
    Noise(String),
    #[error("replay rejected: {0}")]
    Replay(&'static str),
    #[error("random generator failed: {0}")]
    Random(&'static str),
    #[error("yaml parse error: {0}")]
    Yaml(#[from] serde_yaml_ng::Error),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
