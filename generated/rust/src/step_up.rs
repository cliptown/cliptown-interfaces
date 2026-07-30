use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub const EXTERNAL_STEP_UP_PROTOCOL_VERSION: u32 = 1;
pub const MAX_EXTERNAL_STEP_UP_LIFETIME_SECONDS: i64 = 5 * 60;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExternalStepUpAction {
    EnrollDevice,
    RevokeDevice,
    UpdateSecuritySettings,
    ChangeRecoveryChannel,
    ExportAppVault,
    RecoverAccount,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExternalStepUpProof {
    pub protocol_version: u32,
    pub proof_id: String,
    pub issuer: String,
    pub subject: String,
    pub audience: String,
    pub device_id: String,
    pub challenge_id: String,
    pub action: ExternalStepUpAction,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub signing_key_id: String,
    pub signature: String,
}

impl ExternalStepUpProof {
    pub fn validate(&self, now: Option<DateTime<Utc>>) -> Result<(), String> {
        if self.protocol_version != EXTERNAL_STEP_UP_PROTOCOL_VERSION {
            return Err("unsupported external step-up proof version".into());
        }
        require_portable_identifier(&self.proof_id, "proof_id")?;
        require_bounded_text(&self.issuer, "issuer", 256)?;
        require_portable_identifier(&self.subject, "subject")?;
        if self.audience != "cliptown" {
            return Err("external step-up proof has the wrong audience".into());
        }
        require_portable_identifier(&self.device_id, "device_id")?;
        require_portable_identifier(&self.challenge_id, "challenge_id")?;
        require_portable_identifier(&self.signing_key_id, "signing_key_id")?;
        let lifetime = self
            .expires_at
            .signed_duration_since(self.issued_at)
            .num_seconds();
        if !(1..=MAX_EXTERNAL_STEP_UP_LIFETIME_SECONDS).contains(&lifetime) {
            return Err("external step-up proof lifetime is invalid".into());
        }
        if let Some(now) = now {
            if self.expires_at <= now {
                return Err("external step-up proof has expired".into());
            }
            if self.issued_at > now + chrono::Duration::minutes(5) {
                return Err("external step-up proof is not yet valid".into());
            }
        }
        if !(43..=684).contains(&self.signature.len()) {
            return Err("external step-up signature length is invalid".into());
        }
        Ok(())
    }
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

fn require_bounded_text(value: &str, field: &str, max_len: usize) -> Result<(), String> {
    if value.is_empty()
        || value.len() > max_len
        || value
            .chars()
            .any(|character| character.is_control())
    {
        return Err(format!("{field} is empty, oversized, or contains control characters"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proof() -> ExternalStepUpProof {
        ExternalStepUpProof {
            protocol_version: EXTERNAL_STEP_UP_PROTOCOL_VERSION,
            proof_id: "proof-1".into(),
            issuer: "https://3fa.app".into(),
            subject: "shared-user-1".into(),
            audience: "cliptown".into(),
            device_id: "device-a".into(),
            challenge_id: "challenge-1".into(),
            action: ExternalStepUpAction::RevokeDevice,
            issued_at: DateTime::parse_from_rfc3339("2026-07-30T12:00:00Z")
                .unwrap()
                .with_timezone(&Utc),
            expires_at: DateTime::parse_from_rfc3339("2026-07-30T12:02:00Z")
                .unwrap()
                .with_timezone(&Utc),
            signing_key_id: "device-signing-key-1".into(),
            signature: "A".repeat(88),
        }
    }

    #[test]
    fn proof_is_single_action_audience_and_lifetime_bound() {
        let proof = proof();
        assert_eq!(proof.validate(Some(proof.issued_at)), Ok(()));

        let mut wrong_audience = proof.clone();
        wrong_audience.audience = "another-product".into();
        assert!(wrong_audience.validate(None).is_err());

        let mut too_long = proof;
        too_long.expires_at = too_long.issued_at + chrono::Duration::minutes(6);
        assert!(too_long.validate(None).is_err());
    }

    #[test]
    fn unknown_fields_cannot_turn_a_proof_into_a_bearer_token() {
        let mut json = serde_json::to_value(proof()).unwrap();
        json.as_object_mut().unwrap().insert(
            "access_token".into(),
            serde_json::Value::String("do-not-accept".into()),
        );
        assert!(serde_json::from_value::<ExternalStepUpProof>(json).is_err());
    }
}
