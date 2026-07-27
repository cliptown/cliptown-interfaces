enum DeviceLifecycleState { pending, active, suspended, revoked }
enum RecoveryChannelKind { email, phone }
enum SignalEnvelopePurpose {
  accountKeyTransfer,
  clipKey,
  objectKey,
  deviceControl,
  recoveryPackage,
  acknowledgement,
}

class PinKdfPolicy {
  const PinKdfPolicy({
    required this.algorithm,
    required this.memoryKib,
    required this.iterations,
    required this.parallelism,
    required this.maxAttempts,
    required this.lockoutSeconds,
  });

  final String algorithm;
  final int memoryKib;
  final int iterations;
  final int parallelism;
  final int maxAttempts;
  final int lockoutSeconds;
}

class LocalUnlockPolicy {
  const LocalUnlockPolicy({
    required this.pinEnabled,
    required this.biometricEnabled,
    required this.passkeyEnabled,
    this.pinKdf,
  });

  final bool pinEnabled;
  final bool biometricEnabled;
  final bool passkeyEnabled;
  final PinKdfPolicy? pinKdf;

  void validate() {
    if (pinEnabled && pinKdf == null) {
      throw ArgumentError('PIN unlock requires a bounded KDF policy');
    }
    final kdf = pinKdf;
    if (kdf != null &&
        (!const <String>{'argon2id-v1', 'scrypt-v1'}.contains(kdf.algorithm) ||
            kdf.memoryKib < 8192 ||
            kdf.memoryKib > 1048576 ||
            kdf.iterations < 1 ||
            kdf.iterations > 20 ||
            kdf.parallelism < 1 ||
            kdf.parallelism > 8 ||
            kdf.maxAttempts < 3 ||
            kdf.maxAttempts > 20)) {
      throw ArgumentError('PIN KDF/throttling policy is outside supported bounds');
    }
  }
}

class SignalEnvelopeMetadata {
  const SignalEnvelopeMetadata({
    required this.protocolVersion,
    required this.envelopeId,
    required this.accountId,
    required this.senderDeviceId,
    required this.recipientDeviceId,
    required this.sessionId,
    required this.messageNumber,
    required this.purpose,
    required this.createdAt,
    required this.expiresAt,
  });

  final int protocolVersion;
  final String envelopeId;
  final String accountId;
  final String senderDeviceId;
  final String recipientDeviceId;
  final String sessionId;
  final int messageNumber;
  final SignalEnvelopePurpose purpose;
  final DateTime createdAt;
  final DateTime expiresAt;
}

class SignalCiphertextEnvelope {
  const SignalCiphertextEnvelope({
    required this.metadata,
    required this.ciphertext,
  });

  final SignalEnvelopeMetadata metadata;
  final String ciphertext;

  void validate() {
    if (metadata.protocolVersion != 1 ||
        metadata.envelopeId.isEmpty ||
        metadata.sessionId.isEmpty ||
        metadata.sessionId.length > 128 ||
        metadata.senderDeviceId == metadata.recipientDeviceId ||
        metadata.messageNumber < 0 ||
        ciphertext.isEmpty ||
        ciphertext.length > 699052 ||
        !metadata.expiresAt.isAfter(metadata.createdAt)) {
      throw ArgumentError('invalid Signal ciphertext envelope');
    }
  }
}

class WrappedContentKey {
  const WrappedContentKey({
    required this.recipientDeviceId,
    required this.keyId,
    required this.algorithm,
    required this.nonce,
    required this.wrappedKey,
    required this.associatedDataHash,
  });

  final String recipientDeviceId;
  final String keyId;
  final String algorithm;
  final String nonce;
  final String wrappedKey;
  final String associatedDataHash;
}

class EncryptedObjectChunk {
  const EncryptedObjectChunk({
    required this.chunkIndex,
    required this.ciphertextLength,
    required this.ciphertextSha256,
    required this.nonce,
    required this.randomizedStorageKey,
  });

  final int chunkIndex;
  final int ciphertextLength;
  final String ciphertextSha256;
  final String nonce;
  final String randomizedStorageKey;
}

class EncryptedObjectManifest {
  const EncryptedObjectManifest({
    required this.manifestId,
    required this.objectId,
    required this.clipId,
    required this.contentCipherVersion,
    required this.plaintextLength,
    required this.ciphertextLength,
    required this.chunkSize,
    required this.chunks,
    required this.wrappedKeys,
    required this.encryptedMetadata,
    required this.ciphertextSha256,
    required this.createdAt,
  });

  final String manifestId;
  final String objectId;
  final String clipId;
  final String contentCipherVersion;
  final int plaintextLength;
  final int ciphertextLength;
  final int chunkSize;
  final List<EncryptedObjectChunk> chunks;
  final List<WrappedContentKey> wrappedKeys;
  final Object encryptedMetadata;
  final String ciphertextSha256;
  final DateTime createdAt;

  void validate() {
    if (chunks.isEmpty || wrappedKeys.isEmpty) {
      throw ArgumentError('encrypted objects require chunks and wrapped keys');
    }
    if (chunkSize < 65536 || chunkSize > 16777216) {
      throw ArgumentError('chunkSize is outside supported bounds');
    }
    for (var index = 0; index < chunks.length; index += 1) {
      final chunk = chunks[index];
      if (chunk.chunkIndex != index ||
          chunk.ciphertextLength <= 0 ||
          chunk.ciphertextSha256.isEmpty ||
          chunk.nonce.isEmpty ||
          chunk.randomizedStorageKey.length < 16 ||
          chunk.randomizedStorageKey.length > 512) {
        throw ArgumentError('encrypted object chunks must be contiguous and complete');
      }
    }
    if (wrappedKeys.map((key) => key.recipientDeviceId).toSet().length != wrappedKeys.length) {
      throw ArgumentError('wrapped keys must be unique per recipient device');
    }
  }
}
