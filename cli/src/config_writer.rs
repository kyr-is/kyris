// SPDX-FileCopyrightText: Copyright 2026 Kyris
// SPDX-License-Identifier: Apache-2.0
//! Pre-write validation framework for managed config files.
//!
//! Every file kyris writes goes through `state::write_managed_file`, which now
//! takes a `&dyn ConfigValidator`. The validator inspects the proposed
//! contents in memory and returns `Ok(())` only if the write should proceed.
//! No disk mutation happens until validation passes; combined with the atomic
//! write below, a failed validation is a no-op rather than a partial corruption.
//!
//! A handful of built-in validators cover the common cases:
//!
//! - `NoopValidator` — for genuinely opaque files (shell scripts, binaries,
//!   `.rules` text). Explicit opt-out from validation.
//! - `WellFormedTomlValidator` / `WellFormedJsonValidator` /
//!   `WellFormedYamlValidator` — minimum: contents parse as that format.
//!   Cheap insurance against serializer bugs.
//! - `TomlShapeValidator<T>` / `JsonShapeValidator<T>` /
//!   `YamlShapeValidator<T>` — generic over a Rust struct that mirrors the
//!   keys we care about. Fields kyris doesn't own should be tolerated via
//!   `#[serde(flatten)] _rest: HashMap<String, Value>` so unknown keys added
//!   by upstream releases don't break validation.
//! - `JsonSchemaValidator` — validates against a JSON Schema (Draft 2020-12 by
//!   default). Useful when the upstream tool publishes one.
//! - `CommandValidator` — shells out to an external validator (e.g.
//!   `tool --check-config <file>`). Slowest, highest fidelity.
//! - `ChainValidator` — runs validators in order, short-circuits on first
//!   failure.

use std::any::type_name;
use std::marker::PhantomData;
use std::process::Command;

use serde::de::DeserializeOwned;

#[derive(Debug, Clone)]
pub struct ValidationError {
    pub validator: &'static str,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{}] {}", self.validator, self.message)
    }
}

impl std::error::Error for ValidationError {}

impl ValidationError {
    pub fn new(validator: &'static str, message: impl Into<String>) -> Self {
        Self {
            validator,
            message: message.into(),
        }
    }
}

/// Object-safe trait. Implementations must be Send + Sync to allow
/// `&dyn ConfigValidator` to be shared across threads.
pub trait ConfigValidator: Send + Sync {
    fn validate(&self, contents: &str) -> Result<(), ValidationError>;
    /// Stable identifier used in error messages and telemetry.
    fn kind(&self) -> &'static str;
    /// True if `validate` always returns `Ok` regardless of input. Lets binary
    /// callers skip the UTF-8 lossy decode they would otherwise need to feed
    /// the validator. Defaults to false; only `NoopValidator` overrides.
    fn is_noop(&self) -> bool {
        false
    }
}

// -- NoopValidator --------------------------------------------------------

/// Skips validation. Use only for files that genuinely have no schema:
/// shell scripts, binaries, opaque text (e.g. compiled `.rules` files).
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopValidator;

impl ConfigValidator for NoopValidator {
    fn validate(&self, _contents: &str) -> Result<(), ValidationError> {
        Ok(())
    }
    fn kind(&self) -> &'static str {
        "Noop"
    }
    fn is_noop(&self) -> bool {
        true
    }
}

// -- Well-formedness validators ------------------------------------------

#[derive(Debug, Default, Clone, Copy)]
#[allow(dead_code)] // Public framework API — used by tests; reserved for callers that switch from NoopValidator.
pub struct WellFormedTomlValidator;

impl ConfigValidator for WellFormedTomlValidator {
    fn validate(&self, contents: &str) -> Result<(), ValidationError> {
        toml::from_str::<toml::Value>(contents)
            .map(|_| ())
            .map_err(|e| ValidationError::new("WellFormedToml", e.to_string()))
    }
    fn kind(&self) -> &'static str {
        "WellFormedToml"
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct WellFormedJsonValidator;

impl ConfigValidator for WellFormedJsonValidator {
    fn validate(&self, contents: &str) -> Result<(), ValidationError> {
        serde_json::from_str::<serde_json::Value>(contents)
            .map(|_| ())
            .map_err(|e| ValidationError::new("WellFormedJson", e.to_string()))
    }
    fn kind(&self) -> &'static str {
        "WellFormedJson"
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct WellFormedYamlValidator;

impl ConfigValidator for WellFormedYamlValidator {
    fn validate(&self, contents: &str) -> Result<(), ValidationError> {
        serde_saphyr::from_str::<serde_json::Value>(contents)
            .map(|_| ())
            .map_err(|e| ValidationError::new("WellFormedYaml", e.to_string()))
    }
    fn kind(&self) -> &'static str {
        "WellFormedYaml"
    }
}

// -- Shape validators (deserialize into T) -------------------------------

/// Validates that the proposed contents deserialize cleanly into `T`. T should
/// mirror the keys kyris owns and tolerate unknown keys via
/// `#[serde(flatten)] _rest: HashMap<String, toml::Value>` so upstream
/// additions don't break validation.
pub struct TomlShapeValidator<T> {
    _phantom: PhantomData<fn() -> T>,
}

impl<T> Default for TomlShapeValidator<T> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T> TomlShapeValidator<T> {
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T> ConfigValidator for TomlShapeValidator<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    fn validate(&self, contents: &str) -> Result<(), ValidationError> {
        toml::from_str::<T>(contents)
            .map(|_| ())
            .map_err(|e| ValidationError::new(self.kind(), format!("{} ({})", e, type_name::<T>())))
    }
    fn kind(&self) -> &'static str {
        "TomlShape"
    }
}

pub struct JsonShapeValidator<T> {
    _phantom: PhantomData<fn() -> T>,
}

impl<T> Default for JsonShapeValidator<T> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T> JsonShapeValidator<T> {
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T> ConfigValidator for JsonShapeValidator<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    fn validate(&self, contents: &str) -> Result<(), ValidationError> {
        serde_json::from_str::<T>(contents)
            .map(|_| ())
            .map_err(|e| ValidationError::new(self.kind(), format!("{} ({})", e, type_name::<T>())))
    }
    fn kind(&self) -> &'static str {
        "JsonShape"
    }
}

#[allow(dead_code)] // Public framework API — reserved for YAML configs.
pub struct YamlShapeValidator<T> {
    _phantom: PhantomData<fn() -> T>,
}

impl<T> Default for YamlShapeValidator<T> {
    fn default() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

#[allow(dead_code)]
impl<T> YamlShapeValidator<T> {
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<T> ConfigValidator for YamlShapeValidator<T>
where
    T: DeserializeOwned + Send + Sync + 'static,
{
    fn validate(&self, contents: &str) -> Result<(), ValidationError> {
        serde_saphyr::from_str::<T>(contents)
            .map(|_| ())
            .map_err(|e| ValidationError::new(self.kind(), format!("{} ({})", e, type_name::<T>())))
    }
    fn kind(&self) -> &'static str {
        "YamlShape"
    }
}

// -- JSON Schema validator ------------------------------------------------

/// Validates the proposed contents (parsed as JSON) against a JSON Schema.
/// Use when the upstream tool publishes a schema (e.g. Anthropic ships a
/// settings.json schema for Claude Code).
#[allow(dead_code)] // Public framework API — used when an agent ships a JSON Schema.
pub struct JsonSchemaValidator {
    schema: jsonschema::Validator,
}

#[allow(dead_code)]
impl JsonSchemaValidator {
    pub fn from_schema_str(schema_str: &str) -> Result<Self, String> {
        let schema_value: serde_json::Value =
            serde_json::from_str(schema_str).map_err(|e| format!("invalid JSON in schema: {e}"))?;
        let schema = jsonschema::validator_for(&schema_value)
            .map_err(|e| format!("invalid JSON Schema: {e}"))?;
        Ok(Self { schema })
    }

    pub fn from_schema_value(schema_value: &serde_json::Value) -> Result<Self, String> {
        let schema = jsonschema::validator_for(schema_value)
            .map_err(|e| format!("invalid JSON Schema: {e}"))?;
        Ok(Self { schema })
    }
}

impl ConfigValidator for JsonSchemaValidator {
    fn validate(&self, contents: &str) -> Result<(), ValidationError> {
        let value: serde_json::Value = serde_json::from_str(contents)
            .map_err(|e| ValidationError::new(self.kind(), format!("not valid JSON: {e}")))?;
        let errors: Vec<String> = self
            .schema
            .iter_errors(&value)
            .map(|e| format!("{}: {}", e.instance_path, e))
            .collect();
        if errors.is_empty() {
            Ok(())
        } else {
            Err(ValidationError::new(self.kind(), errors.join("; ")))
        }
    }
    fn kind(&self) -> &'static str {
        "JsonSchema"
    }
}

// -- External command validator ------------------------------------------

/// Writes the proposed contents to a temp file and shells out to an external
/// validator (e.g. `tool --check-config <path>`). The placeholder `{file}`
/// in the command args is substituted with the temp file's path. Exit code 0
/// means valid.
#[allow(dead_code)] // Public framework API — reserved for agents shipping their own validator binary.
pub struct CommandValidator {
    program: String,
    args: Vec<String>,
    /// Used as the temp file extension — pick `toml`, `json`, `yaml`, etc. so
    /// tools that key behavior off file extension still work.
    extension: String,
}

#[allow(dead_code)]
impl CommandValidator {
    pub fn new(
        program: impl Into<String>,
        args: Vec<String>,
        extension: impl Into<String>,
    ) -> Self {
        Self {
            program: program.into(),
            args,
            extension: extension.into(),
        }
    }
}

impl ConfigValidator for CommandValidator {
    fn validate(&self, contents: &str) -> Result<(), ValidationError> {
        let mut tmp = tempfile::Builder::new()
            .suffix(&format!(".{}", self.extension))
            .tempfile()
            .map_err(|e| ValidationError::new(self.kind(), format!("tempfile: {e}")))?;
        std::io::Write::write_all(&mut tmp, contents.as_bytes())
            .map_err(|e| ValidationError::new(self.kind(), format!("write tempfile: {e}")))?;
        let path_str = tmp.path().display().to_string();
        let resolved_args: Vec<String> = self
            .args
            .iter()
            .map(|a| a.replace("{file}", &path_str))
            .collect();
        let output = Command::new(&self.program)
            .args(&resolved_args)
            .output()
            .map_err(|e| {
                ValidationError::new(self.kind(), format!("spawn {}: {e}", self.program))
            })?;
        if output.status.success() {
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(ValidationError::new(
                self.kind(),
                format!(
                    "{} exited {}: {}",
                    self.program,
                    output.status,
                    stderr.trim()
                ),
            ))
        }
    }
    fn kind(&self) -> &'static str {
        "Command"
    }
}

// -- Composition ----------------------------------------------------------

/// Runs validators in order, short-circuiting on first failure. The caller
/// owns the inner validators (boxed for object-safety).
#[allow(dead_code)] // Public framework API — used in tests, reserved for production composition.
pub struct ChainValidator {
    validators: Vec<Box<dyn ConfigValidator>>,
}

#[allow(dead_code)]
impl ChainValidator {
    pub fn new(validators: Vec<Box<dyn ConfigValidator>>) -> Self {
        Self { validators }
    }
}

impl ConfigValidator for ChainValidator {
    fn validate(&self, contents: &str) -> Result<(), ValidationError> {
        for v in &self.validators {
            v.validate(contents)?;
        }
        Ok(())
    }
    fn kind(&self) -> &'static str {
        "Chain"
    }
}

// -- Tests ---------------------------------------------------------------

#[cfg(test)]
#[allow(dead_code)] // Test fixtures are populated by serde, not read by Rust code.
mod tests {
    use super::*;
    use serde::Deserialize;
    use std::collections::HashMap;

    #[test]
    fn testNoopAcceptsAnything() {
        assert!(NoopValidator.validate("").is_ok());
        assert!(NoopValidator.validate("not even valid json {{{").is_ok());
    }

    #[test]
    fn testWellFormedTomlAcceptsValidRejectsInvalid() {
        assert!(WellFormedTomlValidator.validate("[a]\nb = 1").is_ok());
        assert!(WellFormedTomlValidator.validate("[a\nb = 1").is_err());
    }

    #[test]
    fn testWellFormedJsonAcceptsValidRejectsInvalid() {
        assert!(WellFormedJsonValidator.validate(r#"{"a": 1}"#).is_ok());
        assert!(WellFormedJsonValidator.validate(r#"{"a": }"#).is_err());
    }

    #[test]
    fn testWellFormedYamlAcceptsValidRejectsInvalid() {
        assert!(WellFormedYamlValidator.validate("a: 1\nb: 2\n").is_ok());
        // YAML is permissive; a string parses as scalar. Use unbalanced flow
        // syntax to force a parse error.
        assert!(WellFormedYamlValidator.validate("[a, b").is_err());
    }

    #[derive(Debug, Deserialize)]
    struct TestShape {
        name: String,
        count: u32,
        #[serde(flatten)]
        _rest: HashMap<String, toml::Value>,
    }

    #[test]
    fn testTomlShapeAcceptsKnownFieldsToleratesUnknown() {
        let v = TomlShapeValidator::<TestShape>::new();
        assert!(
            v.validate("name = \"x\"\ncount = 7\nfuture_field = true\n")
                .is_ok()
        );
    }

    #[test]
    fn testTomlShapeRejectsTypeMismatch() {
        let v = TomlShapeValidator::<TestShape>::new();
        // count must be u32 — string fails
        let err = v
            .validate("name = \"x\"\ncount = \"not-a-number\"\n")
            .unwrap_err();
        assert_eq!(err.validator, "TomlShape");
    }

    #[test]
    fn testTomlShapeRejectsMissingRequiredField() {
        let v = TomlShapeValidator::<TestShape>::new();
        let err = v.validate("count = 7\n").unwrap_err();
        assert_eq!(err.validator, "TomlShape");
    }

    #[derive(Debug, Deserialize)]
    struct JsonTestShape {
        kind: String,
        #[serde(flatten)]
        _rest: HashMap<String, serde_json::Value>,
    }

    #[test]
    fn testJsonShapeAcceptsKnownFieldsToleratesUnknown() {
        let v = JsonShapeValidator::<JsonTestShape>::new();
        assert!(v.validate(r#"{"kind":"a","extra":42}"#).is_ok());
    }

    #[test]
    fn testJsonSchemaValidatesAgainstSchema() {
        let schema = r#"{
            "type": "object",
            "properties": { "n": { "type": "integer", "minimum": 0 } },
            "required": ["n"]
        }"#;
        let v = JsonSchemaValidator::from_schema_str(schema).unwrap();
        assert!(v.validate(r#"{"n":5}"#).is_ok());
        assert!(v.validate(r#"{"n":-1}"#).is_err());
        assert!(v.validate(r"{}").is_err());
    }

    #[test]
    fn testChainShortCircuitsOnFirstFailure() {
        let chain = ChainValidator::new(vec![
            Box::new(WellFormedJsonValidator),
            Box::new(JsonShapeValidator::<JsonTestShape>::new()),
        ]);
        // well-formed but missing required field
        let err = chain.validate(r#"{"other": 1}"#).unwrap_err();
        assert_eq!(err.validator, "JsonShape");
        // not well-formed — fails first validator
        let err = chain.validate("not json").unwrap_err();
        assert_eq!(err.validator, "WellFormedJson");
    }

    #[test]
    fn testCommandValidatorShellsOut() {
        // /usr/bin/true exits 0 always — every input is "valid".
        let v = CommandValidator::new(
            "/usr/bin/true",
            vec!["{file}".to_string()],
            "txt".to_string(),
        );
        assert!(v.validate("anything").is_ok());

        // /usr/bin/false exits 1 always — every input is "invalid".
        let v = CommandValidator::new(
            "/usr/bin/false",
            vec!["{file}".to_string()],
            "txt".to_string(),
        );
        let err = v.validate("anything").unwrap_err();
        assert_eq!(err.validator, "Command");
    }
}
