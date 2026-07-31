export const EXTERNAL_STEP_UP_PROTOCOL_VERSION = 1 as const;
export const MAX_EXTERNAL_STEP_UP_LIFETIME_MS = 5 * 60 * 1000;

export type ExternalStepUpAction =
  | 'enroll_device'
  | 'revoke_device'
  | 'update_security_settings'
  | 'change_recovery_channel'
  | 'export_app_vault'
  | 'recover_account';

export interface ExternalStepUpProof {
  protocol_version: 1;
  proof_id: string;
  issuer: string;
  subject: string;
  audience: 'cliptown';
  device_id: string;
  challenge_id: string;
  action: ExternalStepUpAction;
  issued_at: string;
  expires_at: string;
  signing_key_id: string;
  signature: string;
}

export function validateExternalStepUpProof(proof: ExternalStepUpProof, nowMs?: number): void {
  if (proof.protocol_version !== EXTERNAL_STEP_UP_PROTOCOL_VERSION) {
    throw new Error('unsupported external step-up proof version');
  }
  requirePortableIdentifier(proof.proof_id, 'proof_id');
  if (!proof.issuer || proof.issuer.length > 256 || /[\u0000-\u001f\u007f-\u009f]/u.test(proof.issuer)) {
    throw new Error('issuer is empty, oversized, or contains control characters');
  }
  requirePortableIdentifier(proof.subject, 'subject');
  if (proof.audience !== 'cliptown') {
    throw new Error('external step-up proof has the wrong audience');
  }
  requirePortableIdentifier(proof.device_id, 'device_id');
  requirePortableIdentifier(proof.challenge_id, 'challenge_id');
  requirePortableIdentifier(proof.signing_key_id, 'signing_key_id');

  const issuedAt = Date.parse(proof.issued_at);
  const expiresAt = Date.parse(proof.expires_at);
  const lifetime = expiresAt - issuedAt;
  if (!Number.isFinite(issuedAt) || !Number.isFinite(expiresAt) || lifetime < 1 || lifetime > MAX_EXTERNAL_STEP_UP_LIFETIME_MS) {
    throw new Error('external step-up proof lifetime is invalid');
  }
  if (nowMs != null) {
    if (!Number.isFinite(nowMs) || issuedAt > nowMs + MAX_EXTERNAL_STEP_UP_LIFETIME_MS) {
      throw new Error('external step-up proof is not yet valid');
    }
    if (expiresAt <= nowMs) {
      throw new Error('external step-up proof has expired');
    }
  }
  if (proof.signature.length < 43 || proof.signature.length > 684) {
    throw new Error('external step-up signature length is invalid');
  }
}

function requirePortableIdentifier(value: string, field: string): void {
  if (!/^[A-Za-z0-9._:-]{1,128}$/.test(value)) {
    throw new Error(`${field} must use bounded portable ASCII characters`);
  }
}
