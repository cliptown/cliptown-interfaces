mod security;
pub use security::*;

use std::collections::HashSet;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ClipKind {
    Text,
    Html,
    Rtf,
    Image,
    File,
    FileList,
    Url,
    Color,
    Json,
}

impl ClipKind {
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Text => "text",
            Self::Html => "html",
            Self::Rtf => "rtf",
            Self::Image => "image",
            Self::File => "file",
            Self::FileList => "file_list",
            Self::Url => "url",
            Self::Color => "color",
            Self::Json => "json",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SearchPrivacyMode {
    LocalOnly,
    BlindIndex,
    OptInVector,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CipherEnvelope {
    pub algorithm: String,
    pub nonce: String,
    pub ciphertext: String,
    pub associated_data_hash: Option<String>,
    pub key_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClipEnvelope {
    pub clip_id: Uuid,
    pub kind: ClipKind,
    pub payload: CipherEnvelope,
    #[serde(default)]
    pub pinned: bool,
    #[serde(default)]
    pub deleted: bool,
    #[serde(default)]
    pub blind_terms: Vec<String>,
    pub opt_in_embedding: Option<Vec<f32>>,
    pub source_app: Option<String>,
    pub source_device_id: Uuid,
    pub logical_clock: i64,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl ClipEnvelope {
    pub fn validate(&self) -> Result<(), String> {
        if self.logical_clock < 0 {
            return Err("logical_clock must be non-negative".into());
        }
        if self.updated_at < self.created_at {
            return Err("updated_at cannot be earlier than created_at".into());
        }
        if !matches!(
            self.payload.algorithm.as_str(),
            "xchacha20poly1305-v1" | "aes-256-gcm-v1"
        ) {
            return Err("unsupported ciphertext algorithm".into());
        }
        if self.payload.nonce.is_empty()
            || self.payload.ciphertext.is_empty()
            || self.payload.key_id.is_empty()
            || self.payload.key_id.len() > 128
        {
            return Err("cipher envelope fields are incomplete or invalid".into());
        }
        if self
            .source_app
            .as_ref()
            .is_some_and(|source| source.chars().count() > 256)
        {
            return Err("source_app may contain at most 256 characters".into());
        }
        if self.blind_terms.len() > 256 {
            return Err("blind_terms may contain at most 256 entries".into());
        }
        let mut unique_terms = HashSet::with_capacity(self.blind_terms.len());
        for term in &self.blind_terms {
            if !(16..=128).contains(&term.len()) {
                return Err("blind terms must contain from 16 through 128 characters".into());
            }
            if !unique_terms.insert(term) {
                return Err("blind_terms must not contain duplicates".into());
            }
        }
        if let Some(embedding) = &self.opt_in_embedding {
            if embedding.len() != 1536 {
                return Err("opt_in_embedding must contain exactly 1536 values".into());
            }
            if embedding.iter().any(|value| !value.is_finite()) {
                return Err("opt_in_embedding values must be finite".into());
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct SearchRequest {
    #[serde(default)]
    pub blind_terms: Vec<String>,
    pub query_embedding: Option<Vec<f32>>,
    pub privacy_mode: SearchPrivacyMode,
    #[serde(default = "default_search_limit")]
    pub limit: u32,
    #[serde(default)]
    pub pinned_only: bool,
}

fn default_search_limit() -> u32 {
    20
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SyncCursor {
    pub cursor: Option<String>,
    pub server_sequence: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SecuritySettings {
    pub reauth_interval_days: u32,
    pub reauth_max_days: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct UpdateSecuritySettings {
    pub reauth_interval_days: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn privacy_mode_is_snake_case() {
        assert_eq!(
            serde_json::to_string(&SearchPrivacyMode::BlindIndex).unwrap(),
            "\"blind_index\""
        );
    }

    #[test]
    fn file_list_kind_is_snake_case() {
        assert_eq!(ClipKind::FileList.as_str(), "file_list");
        assert_eq!(
            serde_json::to_string(&ClipKind::FileList).unwrap(),
            "\"file_list\""
        );
    }
}
