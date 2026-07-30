const int appVaultProtocolVersion = 1;
const int maxAppVaultBatch = 500;

class AppVaultCipherEnvelope {
  const AppVaultCipherEnvelope({
    required this.algorithm,
    required this.nonce,
    required this.ciphertext,
    required this.associatedDataHash,
    required this.keyId,
  });

  final String algorithm;
  final String nonce;
  final String ciphertext;
  final String associatedDataHash;
  final String keyId;

  factory AppVaultCipherEnvelope.fromJson(Map<String, Object?> json) =>
      AppVaultCipherEnvelope(
        algorithm: json['algorithm']! as String,
        nonce: json['nonce']! as String,
        ciphertext: json['ciphertext']! as String,
        associatedDataHash: json['associated_data_hash']! as String,
        keyId: json['key_id']! as String,
      );

  Map<String, Object?> toJson() => <String, Object?>{
        'algorithm': algorithm,
        'nonce': nonce,
        'ciphertext': ciphertext,
        'associated_data_hash': associatedDataHash,
        'key_id': keyId,
      };

  void validate() {
    if (!const <String>{
      'xchacha20poly1305-v1',
      'aes-256-gcm-v1',
    }.contains(algorithm)) {
      throw ArgumentError('unsupported app-vault cipher');
    }
    if (nonce.isEmpty ||
        ciphertext.isEmpty ||
        ciphertext.length > 699052 ||
        associatedDataHash.isEmpty ||
        keyId.isEmpty ||
        keyId.length > 128) {
      throw ArgumentError('app-vault cipher envelope is incomplete or oversized');
    }
  }
}

class AppVaultMutation {
  const AppVaultMutation({
    required this.protocolVersion,
    required this.mutationId,
    required this.appId,
    required this.namespace,
    required this.opaqueRecordId,
    required this.deleted,
    required this.sourceDeviceId,
    required this.logicalClock,
    required this.createdAt,
    required this.updatedAt,
    required this.deviceSignature,
    this.payload,
  });

  final int protocolVersion;
  final String mutationId;
  final String appId;
  final String namespace;
  final String opaqueRecordId;
  final AppVaultCipherEnvelope? payload;
  final bool deleted;
  final String sourceDeviceId;
  final int logicalClock;
  final DateTime createdAt;
  final DateTime updatedAt;
  final String deviceSignature;

  factory AppVaultMutation.fromJson(Map<String, Object?> json) {
    final rawPayload = json['payload'];
    return AppVaultMutation(
      protocolVersion: json['protocol_version']! as int,
      mutationId: json['mutation_id']! as String,
      appId: json['app_id']! as String,
      namespace: json['namespace']! as String,
      opaqueRecordId: json['opaque_record_id']! as String,
      payload: rawPayload == null
          ? null
          : AppVaultCipherEnvelope.fromJson(
              (rawPayload as Map<Object?, Object?>).cast<String, Object?>(),
            ),
      deleted: json['deleted']! as bool,
      sourceDeviceId: json['source_device_id']! as String,
      logicalClock: json['logical_clock']! as int,
      createdAt: DateTime.parse(json['created_at']! as String),
      updatedAt: DateTime.parse(json['updated_at']! as String),
      deviceSignature: json['device_signature']! as String,
    );
  }

  Map<String, Object?> toJson() => <String, Object?>{
        'protocol_version': protocolVersion,
        'mutation_id': mutationId,
        'app_id': appId,
        'namespace': namespace,
        'opaque_record_id': opaqueRecordId,
        if (payload != null) 'payload': payload!.toJson(),
        'deleted': deleted,
        'source_device_id': sourceDeviceId,
        'logical_clock': logicalClock,
        'created_at': createdAt.toUtc().toIso8601String(),
        'updated_at': updatedAt.toUtc().toIso8601String(),
        'device_signature': deviceSignature,
      };

  void validate() {
    if (protocolVersion != appVaultProtocolVersion) {
      throw ArgumentError('unsupported app-vault protocol version');
    }
    _requirePortableIdentifier(mutationId, 'mutationId');
    if (!RegExp(r'^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$').hasMatch(appId)) {
      throw ArgumentError('appId must be a bounded reverse-DNS-style identifier');
    }
    _requirePortableIdentifier(namespace, 'namespace');
    if (!RegExp(r'^[A-Za-z0-9_-]{16,128}$').hasMatch(opaqueRecordId)) {
      throw ArgumentError('opaqueRecordId must be a random id or account-keyed digest');
    }
    _requirePortableIdentifier(sourceDeviceId, 'sourceDeviceId');
    if (logicalClock < 0 || updatedAt.isBefore(createdAt)) {
      throw ArgumentError('app-vault mutation clock or timestamps are invalid');
    }
    if (deleted == (payload != null)) {
      throw ArgumentError('a mutation must contain ciphertext or be a tombstone, never both');
    }
    payload?.validate();
    if (deviceSignature.length < 43 || deviceSignature.length > 684) {
      throw ArgumentError('deviceSignature length is invalid');
    }
  }
}

class AppVaultCursor {
  const AppVaultCursor({required this.serverSequence});

  final int serverSequence;

  factory AppVaultCursor.fromJson(Map<String, Object?> json) => AppVaultCursor(
        serverSequence: json['server_sequence']! as int,
      );

  Map<String, Object?> toJson() => <String, Object?>{
        'server_sequence': serverSequence,
      };

  void validate() {
    if (serverSequence < 0) {
      throw ArgumentError('serverSequence must be non-negative');
    }
  }
}

class AppVaultChange {
  const AppVaultChange({required this.serverSequence, required this.mutation});

  final int serverSequence;
  final AppVaultMutation mutation;

  void validate() {
    if (serverSequence < 1) {
      throw ArgumentError('serverSequence must be positive');
    }
    mutation.validate();
  }
}

class AppVaultPushRequest {
  const AppVaultPushRequest({required this.mutations, this.base});

  final List<AppVaultMutation> mutations;
  final AppVaultCursor? base;

  void validate() {
    if (mutations.length > maxAppVaultBatch) {
      throw ArgumentError('app-vault push batch is too large');
    }
    for (final mutation in mutations) {
      mutation.validate();
    }
    base?.validate();
  }
}

class AppVaultPushResponse {
  const AppVaultPushResponse({
    required this.accepted,
    required this.rejectedMutationIds,
    required this.cursor,
  });

  final List<AppVaultMutation> accepted;
  final List<String> rejectedMutationIds;
  final AppVaultCursor cursor;

  void validate() {
    if (accepted.length > maxAppVaultBatch ||
        rejectedMutationIds.length > maxAppVaultBatch) {
      throw ArgumentError('app-vault push result is too large');
    }
    for (final mutation in accepted) {
      mutation.validate();
    }
    for (final id in rejectedMutationIds) {
      _requirePortableIdentifier(id, 'rejectedMutationId');
    }
    cursor.validate();
  }
}

class AppVaultPullRequest {
  const AppVaultPullRequest({this.after, this.limit = 100});

  final AppVaultCursor? after;
  final int limit;

  void validate() {
    after?.validate();
    if (limit < 1 || limit > maxAppVaultBatch) {
      throw ArgumentError('app-vault pull limit is outside supported bounds');
    }
  }
}

class AppVaultPullResponse {
  const AppVaultPullResponse({
    required this.changes,
    required this.cursor,
    required this.hasMore,
  });

  final List<AppVaultChange> changes;
  final AppVaultCursor cursor;
  final bool hasMore;

  void validate() {
    if (changes.length > maxAppVaultBatch) {
      throw ArgumentError('app-vault pull result is too large');
    }
    cursor.validate();
    var previous = 0;
    for (final change in changes) {
      change.validate();
      if (change.serverSequence <= previous ||
          change.serverSequence > cursor.serverSequence) {
        throw ArgumentError(
          'app-vault server sequences must be increasing and cursor-bounded',
        );
      }
      previous = change.serverSequence;
    }
  }
}

void _requirePortableIdentifier(String value, String field) {
  if (!RegExp(r'^[A-Za-z0-9._:-]{1,128}$').hasMatch(value)) {
    throw ArgumentError('$field must use bounded portable ASCII characters');
  }
}
