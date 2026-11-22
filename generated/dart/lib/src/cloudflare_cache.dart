// Cloudflare encrypted text cache policy. No plaintext, decryption or network.
// Unlike Rust, Dart cannot enforce borrow lifetimes: call synchronously and
// do not mutate the passed Uint8List while the policy is inspecting it.
import 'dart:convert';
import 'dart:typed_data';

const int maxCloudTextItems = 2000;
const int maxCloudLogicalBytes = 5 * 1024 * 1024;
const int cloudItemReserveBytes = 512;

const int maxCloudDeviceSequence = 9007199254740990;

/// Pure synchronous preflight over signed per-device mutation metadata.
/// The D1 trigger remains authoritative against races and cache eviction.
int checkedDeviceSequence(int incoming, int? previous) {
  if (incoming <= 0 ||
      incoming > maxCloudDeviceSequence ||
      (previous != null &&
          (previous <= 0 || previous > maxCloudDeviceSequence))) {
    throw const CloudCachePolicyError('invalid_device_sequence');
  }
  if (previous != null && incoming <= previous) {
    throw const CloudCachePolicyError('device_sequence_replay');
  }
  return incoming;
}

class CloudCacheEnvelopeView {
  const CloudCacheEnvelopeView({
    required this.envelopeId,
    required this.serverSequence,
    required this.kind,
    required this.ciphertext,
  });

  final String envelopeId;
  final int serverSequence;
  final String kind;
  final Uint8List ciphertext;
}

class CloudCacheRetention {
  CloudCacheRetention({
    required List<String> retainedIds,
    required List<String> evictedIds,
    required this.logicalBytes,
  })  : retainedIds = List<String>.unmodifiable(retainedIds),
        evictedIds = List<String>.unmodifiable(evictedIds);

  final List<String> retainedIds;
  final List<String> evictedIds;
  final int logicalBytes;
}

class CloudCachePolicyError implements Exception {
  const CloudCachePolicyError(this.code);
  final String code;

  @override
  String toString() => code;
}

int measuredTextCharge(Uint8List ciphertext) {
  if (ciphertext.isEmpty) {
    throw const CloudCachePolicyError('invalid_ciphertext');
  }
  final int charge = ciphertext.lengthInBytes + cloudItemReserveBytes;
  if (charge > maxCloudLogicalBytes) {
    throw const CloudCachePolicyError('size_limit_exceeded');
  }
  return charge;
}

class _ChargedEnvelope {
  const _ChargedEnvelope(this.row, this.charge);
  final CloudCacheEnvelopeView row;
  final int charge;
}

/// Retains newest contiguous prefix exactly matching Rust, TypeScript and D1.
CloudCacheRetention planTextCache(List<CloudCacheEnvelopeView> rows) {
  final Set<String> seen = <String>{};
  final RegExp identifier = RegExp(r'^[A-Za-z0-9_-]{1,128}$');
  final List<_ChargedEnvelope> charged = <_ChargedEnvelope>[];

  for (final CloudCacheEnvelopeView row in rows) {
    if (row.kind != 'text' ||
        !identifier.hasMatch(row.envelopeId) ||
        row.serverSequence <= 0 ||
        !seen.add(row.envelopeId)) {
      throw const CloudCachePolicyError('invalid_cloud_cache');
    }
    charged.add(_ChargedEnvelope(row, measuredTextCharge(row.ciphertext)));
  }
  charged.sort((_ChargedEnvelope a, _ChargedEnvelope b) {
    final int sequence = b.row.serverSequence.compareTo(a.row.serverSequence);
    return sequence != 0
        ? sequence
        : b.row.envelopeId.compareTo(a.row.envelopeId);
  });

  final List<String> retained = <String>[];
  final List<String> evicted = <String>[];
  int cumulative = 0;
  int retainedBytes = 0;

  for (int index = 0; index < charged.length; index += 1) {
    final _ChargedEnvelope row = charged[index];
    cumulative += row.charge;
    if (index < maxCloudTextItems && cumulative <= maxCloudLogicalBytes) {
      retained.add(row.row.envelopeId);
      retainedBytes = cumulative;
    } else {
      evicted.add(row.row.envelopeId);
    }
  }

  return CloudCacheRetention(
    retainedIds: retained,
    evictedIds: evicted,
    logicalBytes: retainedBytes,
  );
}


/// Exact signing array for the enrolled device proof. This only encodes
/// immutable metadata; authentication and Ed25519 signing occur elsewhere.
class DeviceProofSigningFields {
  const DeviceProofSigningFields({
    required this.accountId,
    required this.tenantId,
    required this.applicationId,
    required this.purpose,
    required this.deviceId,
    required this.envelopeId,
    required this.ciphertextDigest,
    required this.mediaKind,
    required this.deviceSequence,
    required this.keyEpoch,
    required this.revocationEpoch,
    required this.issuedAtMs,
    required this.expiresAtMs,
    required this.nonce,
  });

  final String accountId;
  final String tenantId;
  final String applicationId;
  final String purpose;
  final String deviceId;
  final String envelopeId;
  final String ciphertextDigest;
  final String mediaKind;
  final int deviceSequence;
  final int keyEpoch;
  final int revocationEpoch;
  final int issuedAtMs;
  final int expiresAtMs;
  final String nonce;
}

/// UTF-8 JSON array order matches the Cloudflare Worker and Rust/TypeScript.
List<int> canonicalDeviceProofBytes(DeviceProofSigningFields fields) =>
    utf8.encode(jsonEncode(<Object>[
      'cliptown.device_auth.v1',
      fields.accountId,
      fields.tenantId,
      fields.applicationId,
      fields.purpose,
      fields.deviceId,
      fields.envelopeId,
      fields.ciphertextDigest,
      fields.mediaKind,
      fields.deviceSequence,
      fields.keyEpoch,
      fields.revocationEpoch,
      fields.issuedAtMs,
      fields.expiresAtMs,
      fields.nonce,
    ]));
