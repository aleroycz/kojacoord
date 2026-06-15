use thiserror::Error;

#[derive(Debug, Error)]
pub enum HandlerError {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("compression error: {0}")]
    Compression(String),

    #[error("cipher error: {0}")]
    Cipher(String),

    #[error("protocol error: {0}")]
    Protocol(#[from] kojacoord_protocol::ProtocolError),

    #[error("invalid data length: {0}")]
    InvalidDataLength(i32),
}

#[derive(Debug, Error)]
pub enum PipelineError {
    #[error("handler '{0}' not found")]
    HandlerNotFound(String),

    #[error("duplicate handler name '{0}'")]
    DuplicateName(String),
}

#[derive(Debug, Error)]
pub enum CipherError {
    #[error("invalid key/IV length: expected 16 bytes, got {0}")]
    InvalidLength(usize),
}
