use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::CipherEnvelope;

pub const APP_VAULT_PROTOCOL_VERSION: u32 = 1;
pub const MAX_APP_VAULT_BATCH: usize = 500;
pub const MAX_APP_VAULT_CIPHERTEXT_BASE64_LEN: usize = 699_052;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppVaultMutation {
    pub protocol_version: u32,
    pub mutation_id: String,
    pub app_id: String,
    pub namespace: String,
    pub opaque_record_id: String,
    pub payload: Option<CipherEnvelope>,
    pub deleted: bool,
    pub source_device_id: String,
    pub logical_clock: u64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub device_signature: String,
}

impl AppVaultMutation {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != APP_VAULT_PROTOCOL_VERSION {
            return Err("unsupported app-vault protocol version".into());
        }
        require_portable_identifier(&self.mutation_id, "mutation_id")?;
        require_app_id(&self.app_id)?;
        require_portable_identifier(&self.namespace, "namespace")?;
        require_opaque_record_id(&self.opaque_record_id)?;
        require_portable_identifier(&self.source_device_id, "source_device_id")?;
        if self.updated_at < self.created_at {
            return Err("updated_at cannot be earlier than created_at".into());
        }
        if self.deleted == self.payload.is_some() {
            return Err("a mutation must contain ciphertext or be a tombstone, never both".into());
        }
        if let Some(payload) = &self.payload {
            validate_cipher_envelope(payload)?;
        }
        if !(43..=684).contains(&self.device_signature.len()) {
            return Err("device_signature length is invalid".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(deny_unknown_fields)]
pub struct AppVaultCursor {
    pub server_sequence: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppVaultChange {
    pub server_sequence: u64,
    pub mutation: AppVaultMutation,
}

impl AppVaultChange {
    pub fn validate(&self) -> Result<(), String> {
        if self.server_sequence == 0 {
            return Err("server_sequence must be positive".into());
        }
        self.mutation.validate()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppVaultPushRequest {
    pub mutations: Vec<AppVaultMutation>,
    pub base: Option<AppVaultCursor>,
}

impl AppVaultPushRequest {
    pub fn validate(&self) -> Result<(), String> {
        if self.mutations.len() > MAX_APP_VAULT_BATCH {
            return Err("app-vault push batch is too large".into());
        }
        for mutation in &self.mutations {
            mutation.validate()?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppVaultPushResult {
    pub accepted: Vec<AppVaultMutation>,
    pub rejected_mutation_ids: Vec<String>,
    pub cursor: AppVaultCursor,
}

impl AppVaultPushResult {
    pub fn validate(&self) -> Result<(), String> {
        if self.accepted.len() > MAX_APP_VAULT_BATCH
            || self.rejected_mutation_ids.len() > MAX_APP_VAULT_BATCH
        {
            return Err("app-vault push result is too large".into());
        }
        for mutation in &self.accepted {
            mutation.validate()?;
        }
        for id in &self.rejected_mutation_ids {
            require_portable_identifier(id, "rejected_mutation_id")?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppVaultPullRequest {
    pub after: Option<AppVaultCursor>,
    pub limit: u32,
}

impl AppVaultPullRequest {
    pub fn validate(&self) -> Result<(), String> {
        if !(1..=MAX_APP_VAULT_BATCH as u32).contains(&self.limit) {
            return Err("app-vault pull limit is outside supported bounds".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AppVaultPullResult {
    pub changes: Vec<AppVaultChange>,
    pub cursor: AppVaultCursor,
    pub has_more: bool,
}

impl AppVaultPullResult {
    pub fn validate(&self) -> Result<(), String> {
        if self.changes.len() > MAX_APP_VAULT_BATCH {
            return Err("app-vault pull result is too large".into());
        }
        let mut previous = 0;
        for change in &self.changes {
            change.validate()?;
            if change.server_sequence <= previous
                || change.server_sequence > self.cursor.server_sequence
            {
                return Err("app-vault server sequences must be increasing and cursor-bounded".into());
            }
            previous = change.server_sequence;
        }
        Ok(())
    }
}

fn validate_cipher_envelope(payload: &CipherEnvelope) -> Result<(), String> {
    if !matches!(
        payload.algorithm.as_str(),
        "xchacha20poly1305-v1" | "aes-256-gcm-v1"
    ) {
        return Err("unsupported app-vault cipher".into());
    }
    if payload.nonce.is_empty()
        || payload.ciphertext.is_empty()
        || payload.ciphertext.len() > MAX_APP_VAULT_CIPHERTEXT_BASE64_LEN
        || payload.associated_data_hash.as_deref().is_none_or(str::is_empty)
        || payload.key_id.is_empty()
        || payload.key_id.len() > 128
    {
        return Err("app-vault cipher envelope is incomplete or oversized".into());
    }
    Ok(())
}

fn require_portable_identifier(value: &str, field: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
    {
        return Err(format!("{field} must use bounded portable ASCII characters"));
    }
    Ok(())
}

fn require_app_id(value: &str) -> Result<(), String> {
    if value.is_empty()
        || value.len() > 128
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err("app_id must be a bounded reverse-DNS-style identifier".into());
    }
    Ok(())
}

fn require_opaque_record_id(value: &str) -> Result<(), String> {
    if !(16..=128).contains(&value.len())
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("opaque_record_id must be a random id or account-keyed digest".into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mutation() -> AppVaultMutation {
        AppVaultMutation {
            protocol_version: APP_VAULT_PROTOCOL_VERSION,
            mutation_id: "mutation-1".into(),
            app_id: "app.3fa.authenticator".into(),
            namespace: "threefa-vault-v1".into(),
            opaque_record_id: "opaque_record_id_0000000001".into(),
            payload: Some(CipherEnvelope {
                algorithm: "xchacha20poly1305-v1".into(),
                nonce: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".into(),
                ciphertext: "AQIDBA==".into(),
                associated_data_hash: Some(
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".into(),
                ),
                key_id: "key-1".into(),
            }),
            deleted: false,
            source_device_id: "device-a".into(),
            logical_clock: 7,
            created_at: DateTime::parse_from_rfc3339("2026-07-30T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            updated_at: DateTime::parse_from_rfc3339("2026-07-30T12:00:01Z")
                .unwrap()
                .with_timezone(&Utc),
            device_signature: "A".repeat(88),
        }
    }

    #[test]
    fn live_record_and_tombstone_validate() {
        let live = mutation();
        assert_eq!(live.validate(), Ok(()));

        let mut tombstone = live.clone();
        tombstone.payload = None;
        tombstone.deleted = true;
        assert_eq!(tombstone.validate(), Ok(()));
    }

    #[test]
    fn semantic_record_labels_are_rejected() {
        let mut record = mutation();
        record.opaque_record_id = "github:alice".into();
        assert!(record.validate().is_err());
    }

    #[test]
    fn clipboard_fields_cannot_be_deserialized_into_app_vault_records() {
        let mut json = serde_json::to_value(mutation()).unwrap();
        json.as_object_mut()
            .unwrap()
            .insert("pinned".into(), serde_json::Value::Bool(true));
        assert!(serde_json::from_value::<AppVaultMutation>(json).is_err());
    }
}
