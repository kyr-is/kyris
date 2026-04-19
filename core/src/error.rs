// SPDX-License-Identifier: Apache-2.0
use std::fmt;

#[derive(Debug)]
pub enum KyrisError {
    Config(String),
    Storage(String),
    Provider(String),
    Sync(String),
    Auth(String),
    CircuitBreaker(String),
    Io(std::io::Error),
    Json(serde_json::Error),
}

impl fmt::Display for KyrisError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(msg) => write!(f, "config error: {msg}"),
            Self::Storage(msg) => write!(f, "storage error: {msg}"),
            Self::Provider(msg) => write!(f, "provider error: {msg}"),
            Self::Sync(msg) => write!(f, "sync error: {msg}"),
            Self::Auth(msg) => write!(f, "auth error: {msg}"),
            Self::CircuitBreaker(msg) => write!(f, "circuit breaker: {msg}"),
            Self::Io(err) => write!(f, "io error: {err}"),
            Self::Json(err) => write!(f, "json error: {err}"),
        }
    }
}

impl std::error::Error for KyrisError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(err) => Some(err),
            Self::Json(err) => Some(err),
            _ => None,
        }
    }
}

impl From<std::io::Error> for KyrisError {
    fn from(err: std::io::Error) -> Self {
        Self::Io(err)
    }
}

impl From<serde_json::Error> for KyrisError {
    fn from(err: serde_json::Error) -> Self {
        Self::Json(err)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn testErrorDisplay() {
        let err = KyrisError::Config("bad toml".to_string());
        assert_eq!(err.to_string(), "config error: bad toml");
    }

    #[test]
    fn testErrorFromIo() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
        let err = KyrisError::from(io_err);
        assert!(matches!(err, KyrisError::Io(_)));
        assert!(err.to_string().contains("missing"));
    }

    #[test]
    fn testErrorSource() {
        let io_err = std::io::Error::other("test");
        let err = KyrisError::Io(io_err);
        assert!(std::error::Error::source(&err).is_some());

        let config_err = KyrisError::Config("test".to_string());
        assert!(std::error::Error::source(&config_err).is_none());
    }

    #[test]
    fn testErrorDisplayAllVariants() {
        assert_eq!(
            KyrisError::Storage("db down".to_string()).to_string(),
            "storage error: db down"
        );
        assert_eq!(
            KyrisError::Provider("timeout".to_string()).to_string(),
            "provider error: timeout"
        );
        assert_eq!(
            KyrisError::Sync("conflict".to_string()).to_string(),
            "sync error: conflict"
        );
        assert_eq!(
            KyrisError::Auth("forbidden".to_string()).to_string(),
            "auth error: forbidden"
        );
        assert_eq!(
            KyrisError::CircuitBreaker("open".to_string()).to_string(),
            "circuit breaker: open"
        );
    }

    #[test]
    fn testErrorFromJson() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = KyrisError::from(json_err);
        assert!(matches!(err, KyrisError::Json(_)));
        assert!(err.to_string().contains("json error:"));
    }

    #[test]
    fn testErrorSourceJsonVariant() {
        let json_err = serde_json::from_str::<serde_json::Value>("bad").unwrap_err();
        let err = KyrisError::Json(json_err);
        assert!(std::error::Error::source(&err).is_some());
    }

    #[test]
    fn testErrorSourceStringVariantsNone() {
        assert!(std::error::Error::source(&KyrisError::Storage("x".to_string())).is_none());
        assert!(std::error::Error::source(&KyrisError::Provider("x".to_string())).is_none());
        assert!(std::error::Error::source(&KyrisError::Sync("x".to_string())).is_none());
        assert!(std::error::Error::source(&KyrisError::Auth("x".to_string())).is_none());
        assert!(std::error::Error::source(&KyrisError::CircuitBreaker("x".to_string())).is_none());
    }
}
