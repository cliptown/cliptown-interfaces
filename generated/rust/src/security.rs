use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::CipherEnvelope;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DeviceLifecycleState {
    Pending,
    Active,
    Suspended,
    Revoked,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RecoveryChannelKind {
    Email,
    Phone,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SignalEnvelopePurpose {
    AccountKeyTransfer,
    ClipKey,
    ObjectKey,
    DeviceControl,
    RecoveryPackage,
    Acknowledgement,
    AppVaultKey,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PinKdfPolicy {
    pub algorithm: String,
    pub memory_kib: u32,
    pub iterations: u32,
    pub parallelism: u32,
    pub max_attempts: u32,
    pub lockout_seconds: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalUnlockPolicy {
    pub pin_enabled: bool,
    pub biometric_enabled: bool,
    pub passkey_enabled: bool,
    pub pin_kdf: Option<PinKdfPolicy>,
}

impl LocalUnlockPolicy {
    pub fn validate(&self) -> Result<(), String> {
        if self.pin_enabled && self.pin_kdf.is_none() {
            return Err("PIN unlock requires a bounded KDF policy".into());
        }
        if let Some(kdf) = &self.pin_kdf {
            if !matches!(kdf.algorithm.as_str(), "argon2id-v1" | "scrypt-v1")
                || !(8_192..=1_048_576).contains(&kdf.memory_kib)
                || !(1..=20).contains(&kdf.iterations)
                || !(1..=8).contains(&kdf.parallelism)
                || !(3..=20).contains(&kdf.max_attempts)
                || !(1..=86_400).contains(&kdf.lockout_seconds)
            {
                return Err("PIN KDF/throttling policy is outside supported bounds".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignalPreKeyBundle {
    pub device_id: Uuid,
    pub protocol_version: u32,
    pub registration_id: u32,
    pub identity_key: String,
    pub signed_prekey_id: u32,
    pub signed_prekey: String,
    pub signed_prekey_signature: String,
    pub pq_signed_prekey_id: u32,
    pub pq_signed_prekey: String,
    pub pq_signed_prekey_signature: String,
    pub one_time_prekey_id: Option<u32>,
    pub one_time_prekey: Option<String>,
    pub bundle_revision: u64,
    pub published_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

impl SignalPreKeyBundle {
    pub fn validate(&self) -> Result<(), String> {
        if self.protocol_version != 1 || self.registration_id == 0 || self.bundle_revision == 0 {
            return Err("invalid Signal prekey version or revision".into());
        }
        for value in [
            &self.identity_key,
            &self.signed_prekey,
            &self.signed_prekey_signature,
            &self.pq_signed_prekey,
            &self.pq_signed_prekey_signature,
        ] {
            if value.is_empty() || value.len() > 16_384 {
                return Err("public prekey material is empty or oversized".into());
            }
        }
        if self.one_time_prekey_id.is_some() != self.one_time_prekey.is_some() {
            return Err("one-time prekey id and material must appear together".into());
        }
        if self.expires_at <= self.published_at {
            return Err("prekey bundle expiry must follow publication".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DeviceRecord {
    pub device_id: Uuid,
    pub device_name: String,
    pub platform: String,
    pub state: DeviceLifecycleState,
    pub device_list_revision: u64,
    pub identity_key_fingerprint: String,
    pub local_unlock: LocalUnlockPolicy,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub last_seen_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RecoveryChannel {
    pub channel_id: Uuid,
    pub kind: RecoveryChannelKind,
    pub masked_destination: String,
    pub created_at: DateTime<Utc>,
    pub verified_at: Option<DateTime<Utc>>,
    pub disabled_at: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignalEnvelopeMetadata {
    pub protocol_version: u32,
    pub envelope_id: Uuid,
    pub account_id: Uuid,
    pub sender_device_id: Uuid,
    pub recipient_device_id: Uuid,
    pub session_id: String,
    pub message_number: u64,
    pub purpose: SignalEnvelopePurpose,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SignalCiphertextEnvelope {
    pub metadata: SignalEnvelopeMetadata,
    pub ciphertext: String,
}

impl SignalCiphertextEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.metadata.protocol_version != 1
            || self.metadata.sender_device_id == self.metadata.recipient_device_id
            || self.metadata.session_id.is_empty()
            || self.metadata.session_id.len() > 128
            || self.ciphertext.is_empty()
            || self.ciphertext.len() > 699_052
            || self.metadata.expires_at <= self.metadata.created_at
        {
            return Err("invalid Signal ciphertext envelope".into());
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct WrappedContentKey {
    pub recipient_device_id: Uuid,
    pub key_id: String,
    pub algorithm: String,
    pub nonce: String,
    pub wrapped_key: String,
    pub associated_data_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedObjectChunk {
    pub chunk_index: u32,
    pub ciphertext_length: u64,
    pub ciphertext_sha256: String,
    pub nonce: String,
    pub randomized_storage_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct EncryptedObjectManifest {
    pub manifest_id: Uuid,
    pub object_id: Uuid,
    pub clip_id: Uuid,
    pub content_cipher_version: String,
    pub plaintext_length: u64,
    pub ciphertext_length: u64,
    pub chunk_size: u32,
    pub chunks: Vec<EncryptedObjectChunk>,
    pub wrapped_keys: Vec<WrappedContentKey>,
    pub encrypted_metadata: CipherEnvelope,
    pub ciphertext_sha256: String,
    pub created_at: DateTime<Utc>,
}

impl EncryptedObjectManifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.chunks.is_empty() || self.wrapped_keys.is_empty() {
            return Err("encrypted objects require chunks and wrapped keys".into());
        }
        if !(65_536..=16_777_216).contains(&self.chunk_size) {
            return Err("chunk_size is outside supported bounds".into());
        }
        for (position, chunk) in self.chunks.iter().enumerate() {
            if chunk.chunk_index as usize != position
                || chunk.ciphertext_length == 0
                || chunk.ciphertext_sha256.is_empty()
                || chunk.nonce.is_empty()
                || !(16..=512).contains(&chunk.randomized_storage_key.len())
            {
                return Err("encrypted object chunks must be contiguous and complete".into());
            }
        }
        let recipients: HashSet<_> = self
            .wrapped_keys
            .iter()
            .map(|key| key.recipient_device_id)
            .collect();
        if recipients.len() != self.wrapped_keys.len() {
            return Err("wrapped keys must be unique per recipient device".into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_is_only_a_bounded_local_unlock_policy() {
        let policy = LocalUnlockPolicy {
            pin_enabled: true,
            biometric_enabled: true,
            passkey_enabled: true,
            pin_kdf: Some(PinKdfPolicy {
                algorithm: "argon2id-v1".into(),
                memory_kib: 65_536,
                iterations: 3,
                parallelism: 1,
                max_attempts: 10,
                lockout_seconds: 60,
            }),
        };
        assert!(policy.validate().is_ok());
    }

    #[test]
    fn app_vault_signal_purpose_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&SignalEnvelopePurpose::AppVaultKey).unwrap(),
            "\"app_vault_key\""
        );
    }
}
