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
    Yaml(Box<serde_saphyr::Error>),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
}

impl From<serde_saphyr::Error> for Error {
    fn from(error: serde_saphyr::Error) -> Self {
        // The parser's duplicate-key message repeats the key, which may be an
        // arbitrary private string; report only its location.
        if let serde_saphyr::Error::DuplicateMappingKey { location, .. } = &error {
            return Self::Config(format!(
                "duplicate configuration key at line {}, column {}",
                location.line(),
                location.column()
            ));
        }
        Self::Yaml(Box::new(error))
    }
}

pub type Result<T> = std::result::Result<T, Error>;
