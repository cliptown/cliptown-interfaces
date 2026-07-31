const int externalStepUpProtocolVersion = 1;
const Duration maxExternalStepUpLifetime = Duration(minutes: 5);

enum ExternalStepUpAction {
  enrollDevice,
  revokeDevice,
  updateSecuritySettings,
  changeRecoveryChannel,
  exportAppVault,
  recoverAccount,
}

String externalStepUpActionToWire(ExternalStepUpAction value) => switch (value) {
      ExternalStepUpAction.enrollDevice => 'enroll_device',
      ExternalStepUpAction.revokeDevice => 'revoke_device',
      ExternalStepUpAction.updateSecuritySettings =>
        'update_security_settings',
      ExternalStepUpAction.changeRecoveryChannel => 'change_recovery_channel',
      ExternalStepUpAction.exportAppVault => 'export_app_vault',
      ExternalStepUpAction.recoverAccount => 'recover_account',
    };

ExternalStepUpAction externalStepUpActionFromWire(String value) => switch (value) {
      'enroll_device' => ExternalStepUpAction.enrollDevice,
      'revoke_device' => ExternalStepUpAction.revokeDevice,
      'update_security_settings' =>
        ExternalStepUpAction.updateSecuritySettings,
      'change_recovery_channel' => ExternalStepUpAction.changeRecoveryChannel,
      'export_app_vault' => ExternalStepUpAction.exportAppVault,
      'recover_account' => ExternalStepUpAction.recoverAccount,
      _ => throw FormatException('unknown external step-up action: $value'),
    };

class ExternalStepUpProof {
  const ExternalStepUpProof({
    required this.protocolVersion,
    required this.proofId,
    required this.issuer,
    required this.subject,
    required this.audience,
    required this.deviceId,
    required this.challengeId,
    required this.action,
    required this.issuedAt,
    required this.expiresAt,
    required this.signingKeyId,
    required this.signature,
  });

  final int protocolVersion;
  final String proofId;
  final String issuer;
  final String subject;
  final String audience;
  final String deviceId;
  final String challengeId;
  final ExternalStepUpAction action;
  final DateTime issuedAt;
  final DateTime expiresAt;
  final String signingKeyId;
  final String signature;

  factory ExternalStepUpProof.fromJson(Map<String, Object?> json) =>
      ExternalStepUpProof(
        protocolVersion: json['protocol_version']! as int,
        proofId: json['proof_id']! as String,
        issuer: json['issuer']! as String,
        subject: json['subject']! as String,
        audience: json['audience']! as String,
        deviceId: json['device_id']! as String,
        challengeId: json['challenge_id']! as String,
        action: externalStepUpActionFromWire(json['action']! as String),
        issuedAt: DateTime.parse(json['issued_at']! as String),
        expiresAt: DateTime.parse(json['expires_at']! as String),
        signingKeyId: json['signing_key_id']! as String,
        signature: json['signature']! as String,
      );

  Map<String, Object?> toJson() => <String, Object?>{
        'protocol_version': protocolVersion,
        'proof_id': proofId,
        'issuer': issuer,
        'subject': subject,
        'audience': audience,
        'device_id': deviceId,
        'challenge_id': challengeId,
        'action': externalStepUpActionToWire(action),
        'issued_at': issuedAt.toUtc().toIso8601String(),
        'expires_at': expiresAt.toUtc().toIso8601String(),
        'signing_key_id': signingKeyId,
        'signature': signature,
      };

  void validate({DateTime? now}) {
    if (protocolVersion != externalStepUpProtocolVersion) {
      throw ArgumentError('unsupported external step-up proof version');
    }
    _requirePortableIdentifier(proofId, 'proofId');
    if (issuer.isEmpty ||
        issuer.length > 256 ||
        issuer.runes.any(
          (int rune) => rune < 32 || (rune >= 127 && rune <= 159),
        )) {
      throw ArgumentError(
        'issuer is empty, oversized, or contains control characters',
      );
    }
    _requirePortableIdentifier(subject, 'subject');
    if (audience != 'cliptown') {
      throw ArgumentError('external step-up proof has the wrong audience');
    }
    _requirePortableIdentifier(deviceId, 'deviceId');
    _requirePortableIdentifier(challengeId, 'challengeId');
    _requirePortableIdentifier(signingKeyId, 'signingKeyId');
    final lifetime = expiresAt.difference(issuedAt);
    if (lifetime <= Duration.zero || lifetime > maxExternalStepUpLifetime) {
      throw ArgumentError('external step-up proof lifetime is invalid');
    }
    if (now != null) {
      if (issuedAt.isAfter(now.add(maxExternalStepUpLifetime))) {
        throw ArgumentError('external step-up proof is not yet valid');
      }
      if (!expiresAt.isAfter(now)) {
        throw ArgumentError('external step-up proof has expired');
      }
    }
    if (signature.length < 43 || signature.length > 684) {
      throw ArgumentError('external step-up signature length is invalid');
    }
  }
}

void _requirePortableIdentifier(String value, String field) {
  if (!RegExp(r'^[A-Za-z0-9._:-]{1,128}$').hasMatch(value)) {
    throw ArgumentError('$field must use bounded portable ASCII characters');
  }
}
