//! Borrowed, transport-neutral policy for ClipTown's optional Cloudflare
//! encrypted text cache. No HTTP, credentials, decryption, unsafe or plaintext.
//! Caller must authenticate device identity and verify cryptographic envelope
//! before constructing these views. The local operation log remains primary.

use std::collections::HashSet;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloudCachePolicyError {
    InvalidCloudCache,
    InvalidCiphertext,
    SizeLimitExceeded,
}

impl CloudCachePolicyError {
    pub const fn code(self) -> &'static str {
        match self {
            Self::InvalidCloudCache => "invalid_cloud_cache",
            Self::InvalidCiphertext => "invalid_ciphertext",
            Self::SizeLimitExceeded => "size_limit_exceeded",
        }
    }
}

impl std::fmt::Display for CloudCachePolicyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.code())
    }
}
impl std::error::Error for CloudCachePolicyError {}

pub const MAX_CLOUD_TEXT_ITEMS: usize = 2_000;
pub const MAX_CLOUD_LOGICAL_BYTES: usize = 5 * 1024 * 1024;
pub const PER_CLOUD_ITEM_RESERVE_BYTES: usize = 512;

/// Immutable view: while a Rust caller retains this borrowed ciphertext slice
/// it cannot mutably borrow the original buffer. No copies are required.
#[derive(Debug, Clone, Copy)]
pub struct BorrowedTextEnvelope<'a> {
    pub envelope_id: &'a str,
    pub server_sequence: u64,
    pub kind: &'a str,
    pub ciphertext: &'a [u8],
}

/// Result IDs borrow from input; cannot outlive source storage.
#[derive(Debug, PartialEq, Eq)]
pub struct CloudCacheRetention<'a> {
    pub retained_ids: Vec<&'a str>,
    pub evicted_ids: Vec<&'a str>,
    pub logical_bytes: usize,
}

/// Server-measured ciphertext length + reserved metadata, never caller bytes.
pub fn measured_text_charge(ciphertext: &[u8]) -> Result<usize, CloudCachePolicyError> {
    if ciphertext.is_empty() {
        return Err(CloudCachePolicyError::InvalidCiphertext);
    }
    let charge = ciphertext
        .len()
        .checked_add(PER_CLOUD_ITEM_RESERVE_BYTES)
        .ok_or(CloudCachePolicyError::SizeLimitExceeded)?;
    if charge > MAX_CLOUD_LOGICAL_BYTES {
        return Err(CloudCachePolicyError::SizeLimitExceeded);
    }
    Ok(charge)
}

/// Newest prefix exactly matches the D1 SQL prune query. All rows must
/// already be selected for one authenticated account by the caller.
pub fn plan_text_cache<'a>(
    rows: &'a [BorrowedTextEnvelope<'a>],
) -> Result<CloudCacheRetention<'a>, CloudCachePolicyError> {
    let mut ids = HashSet::with_capacity(rows.len());
    let mut sorted = Vec::with_capacity(rows.len());

    for row in rows {
        if row.kind != "text"
            || row.envelope_id.is_empty()
            || row.envelope_id.len() > 128
            || !row
                .envelope_id
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
            || row.server_sequence == 0
            || !ids.insert(row.envelope_id)
        {
            return Err(CloudCachePolicyError::InvalidCloudCache);
        }
        let charge = measured_text_charge(row.ciphertext)?;
        sorted.push((row, charge));
    }

    sorted.sort_unstable_by(|(a, _), (b, _)| {
        b.server_sequence
            .cmp(&a.server_sequence)
            .then_with(|| b.envelope_id.cmp(a.envelope_id))
    });

    let mut retained = Vec::new();
    let mut evicted = Vec::new();
    let mut cumulative = 0_usize;
    let mut retained_bytes = 0_usize;

    for (index, (row, charge)) in sorted.into_iter().enumerate() {
        cumulative = cumulative
            .checked_add(charge)
            .ok_or(CloudCachePolicyError::SizeLimitExceeded)?;
        if index < MAX_CLOUD_TEXT_ITEMS && cumulative <= MAX_CLOUD_LOGICAL_BYTES {
            retained.push(row.envelope_id);
            retained_bytes = cumulative;
        } else {
            evicted.push(row.envelope_id);
        }
    }

    Ok(CloudCacheRetention {
        retained_ids: retained,
        evicted_ids: evicted,
        logical_bytes: retained_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_account_and_immutable_ciphertext() {
        assert_eq!(
            plan_text_cache(&[]),
            Ok(CloudCacheRetention {
                retained_ids: Vec::new(),
                evicted_ids: Vec::new(),
                logical_bytes: 0,
            })
        );
        let cipher = [11_u8, 12, 13];
        let records = [BorrowedTextEnvelope {
            envelope_id: "a",
            server_sequence: 1,
            kind: "text",
            ciphertext: &cipher,
        }];
        let planned = plan_text_cache(&records);
        assert!(matches!(planned, Ok(ref p) if p.retained_ids == ["a"]));
        assert_eq!(cipher, [11, 12, 13]);
    }

    #[test]
    fn newest_two_thousand_only() {
        let payload = [3_u8];
        let ids = (0..2_001).map(|i| format!("clip_{i}")).collect::<Vec<_>>();
        let rows = ids
            .iter()
            .enumerate()
            .map(|(index, id)| BorrowedTextEnvelope {
                envelope_id: id,
                server_sequence: (index + 1) as u64,
                kind: "text",
                ciphertext: &payload,
            })
            .collect::<Vec<_>>();
        let result = plan_text_cache(&rows);
        assert!(matches!(
            result,
            Ok(ref plan) if plan.retained_ids.len() == MAX_CLOUD_TEXT_ITEMS
                && plan.evicted_ids == ["clip_0"]
        ));
    }

    #[test]
    fn byte_limit_and_prefix_prune_match_d1() {
        let large = vec![7_u8; MAX_CLOUD_LOGICAL_BYTES - 1_024];
        let small = [1_u8];
        let medium = [1_u8; 1_024];
        let rows = [
            BorrowedTextEnvelope {
                envelope_id: "old",
                server_sequence: 1,
                kind: "text",
                ciphertext: &small,
            },
            BorrowedTextEnvelope {
                envelope_id: "new",
                server_sequence: 3,
                kind: "text",
                ciphertext: &large,
            },
            BorrowedTextEnvelope {
                envelope_id: "middle",
                server_sequence: 2,
                kind: "text",
                ciphertext: &medium,
            },
        ];
        assert!(matches!(
            plan_text_cache(&rows),
            Ok(ref p) if p.retained_ids == ["new"] && p.evicted_ids == ["middle", "old"]
        ));
    }

    #[test]
    fn reject_nontext_duplicate_invalid_and_zero_length() {
        let payload = [1_u8];
        let valid = BorrowedTextEnvelope {
            envelope_id: "clip_1",
            server_sequence: 1,
            kind: "text",
            ciphertext: &payload,
        };
        assert_eq!(
            plan_text_cache(&[valid, valid]),
            Err(CloudCachePolicyError::InvalidCloudCache)
        );
        assert_eq!(
            plan_text_cache(&[BorrowedTextEnvelope {
                kind: "file",
                ..valid
            }]),
            Err(CloudCachePolicyError::InvalidCloudCache)
        );
        assert_eq!(
            plan_text_cache(&[BorrowedTextEnvelope {
                envelope_id: "a/b",
                ..valid
            }]),
            Err(CloudCachePolicyError::InvalidCloudCache)
        );
        assert_eq!(
            plan_text_cache(&[BorrowedTextEnvelope {
                server_sequence: 0,
                ..valid
            }]),
            Err(CloudCachePolicyError::InvalidCloudCache)
        );
        assert_eq!(
            plan_text_cache(&[BorrowedTextEnvelope {
                ciphertext: &[],
                ..valid
            }]),
            Err(CloudCachePolicyError::InvalidCiphertext)
        );
    }

    #[test]
    fn oversize_rejected() {
        let huge = vec![2_u8; MAX_CLOUD_LOGICAL_BYTES];
        assert_eq!(
            measured_text_charge(&huge),
            Err(CloudCachePolicyError::SizeLimitExceeded)
        );
    }
}

#[cfg(test)]
mod cross_compiler_fixtures {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    struct FixtureRow {
        envelope_id: String,
        server_sequence: u64,
        kind: String,
        ciphertext_bytes: usize,
    }

    #[derive(Deserialize)]
    struct FixtureCase {
        name: String,
        rows: Vec<FixtureRow>,
        retained_ids: Option<Vec<String>>,
        evicted_ids: Option<Vec<String>>,
        logical_bytes: Option<usize>,
        error: Option<String>,
    }

    #[derive(Deserialize)]
    struct FixtureSet {
        protocol_version: u32,
        cases: Vec<FixtureCase>,
    }

    #[test]
    fn shared_rust_dart_typescript_vectors_match() {
        let input = include_str!("../../../fixtures/cloudflare-text-cache-v1.json");
        let set: FixtureSet = serde_json::from_str(input).expect("fixture JSON");
        assert_eq!(set.protocol_version, 1);

        for case in &set.cases {
            let bytes = case
                .rows
                .iter()
                .map(|row| vec![4_u8; row.ciphertext_bytes])
                .collect::<Vec<_>>();
            let rows = case
                .rows
                .iter()
                .zip(bytes.iter())
                .map(|(row, body)| BorrowedTextEnvelope {
                    envelope_id: &row.envelope_id,
                    server_sequence: row.server_sequence,
                    kind: &row.kind,
                    ciphertext: body,
                })
                .collect::<Vec<_>>();

            match (plan_text_cache(&rows), &case.error) {
                (Ok(plan), None) => {
                    let expected_retained = case
                        .retained_ids
                        .as_ref()
                        .expect("retained ids")
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>();
                    let expected_evicted = case
                        .evicted_ids
                        .as_ref()
                        .expect("evicted ids")
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>();
                    assert_eq!(plan.retained_ids, expected_retained, "case: {}", case.name);
                    assert_eq!(plan.evicted_ids, expected_evicted, "case: {}", case.name);
                    assert_eq!(
                        Some(plan.logical_bytes),
                        case.logical_bytes,
                        "case: {}",
                        case.name
                    );
                }
                (Err(error), Some(code)) => assert_eq!(error.code(), code, "case: {}", case.name),
                (result, expected) => panic!(
                    "cross-compiler case {} expected {:?}, got {:?}",
                    case.name, expected, result
                ),
            }
        }
    }
}
