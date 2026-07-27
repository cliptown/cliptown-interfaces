enum ClipKind { text, html, rtf, image, file, fileList, url, color, json }
enum SearchPrivacyMode { localOnly, blindIndex, optInVector }

String clipKindToWire(ClipKind value) => switch (value) {
      ClipKind.fileList => 'file_list',
      _ => value.name,
    };

ClipKind clipKindFromWire(String value) => switch (value) {
      'file_list' => ClipKind.fileList,
      _ => ClipKind.values.firstWhere((ClipKind item) => item.name == value),
    };

String searchPrivacyModeToWire(SearchPrivacyMode value) => switch (value) {
      SearchPrivacyMode.localOnly => 'local_only',
      SearchPrivacyMode.blindIndex => 'blind_index',
      SearchPrivacyMode.optInVector => 'opt_in_vector',
    };

SearchPrivacyMode searchPrivacyModeFromWire(String value) => switch (value) {
      'local_only' => SearchPrivacyMode.localOnly,
      'blind_index' => SearchPrivacyMode.blindIndex,
      'opt_in_vector' => SearchPrivacyMode.optInVector,
      _ => throw FormatException('unknown search privacy mode: $value'),
    };

class CipherEnvelope {
  const CipherEnvelope({
    required this.algorithm,
    required this.nonce,
    required this.ciphertext,
    required this.keyId,
    this.associatedDataHash,
  });

  final String algorithm;
  final String nonce;
  final String ciphertext;
  final String keyId;
  final String? associatedDataHash;

  factory CipherEnvelope.fromJson(Map<String, Object?> json) => CipherEnvelope(
        algorithm: json['algorithm']! as String,
        nonce: json['nonce']! as String,
        ciphertext: json['ciphertext']! as String,
        keyId: json['key_id']! as String,
        associatedDataHash: json['associated_data_hash'] as String?,
      );

  Map<String, Object?> toJson() => <String, Object?>{
        'algorithm': algorithm,
        'nonce': nonce,
        'ciphertext': ciphertext,
        'key_id': keyId,
        if (associatedDataHash != null) 'associated_data_hash': associatedDataHash,
      };
}

class ClipEnvelope {
  const ClipEnvelope({
    required this.clipId,
    required this.kind,
    required this.payload,
    required this.sourceDeviceId,
    required this.logicalClock,
    required this.createdAt,
    required this.updatedAt,
    this.pinned = false,
    this.deleted = false,
    this.blindTerms = const <String>[],
    this.optInEmbedding,
    this.sourceApp,
  });

  final String clipId;
  final ClipKind kind;
  final CipherEnvelope payload;
  final bool pinned;
  final bool deleted;
  final List<String> blindTerms;
  final List<double>? optInEmbedding;
  final String? sourceApp;
  final String sourceDeviceId;
  final int logicalClock;
  final DateTime createdAt;
  final DateTime updatedAt;

  factory ClipEnvelope.fromJson(Map<String, Object?> json) => ClipEnvelope(
        clipId: json['clip_id']! as String,
        kind: clipKindFromWire(json['kind']! as String),
        payload: CipherEnvelope.fromJson(json['payload']! as Map<String, Object?>),
        pinned: json['pinned'] as bool? ?? false,
        deleted: json['deleted'] as bool? ?? false,
        blindTerms: (json['blind_terms'] as List<Object?>? ?? const <Object?>[]).cast<String>(),
        optInEmbedding: (json['opt_in_embedding'] as List<Object?>?)?.map((Object? value) => (value! as num).toDouble()).toList(growable: false),
        sourceApp: json['source_app'] as String?,
        sourceDeviceId: json['source_device_id']! as String,
        logicalClock: json['logical_clock']! as int,
        createdAt: DateTime.parse(json['created_at']! as String),
        updatedAt: DateTime.parse(json['updated_at']! as String),
      );

  Map<String, Object?> toJson() => <String, Object?>{
        'clip_id': clipId,
        'kind': clipKindToWire(kind),
        'payload': payload.toJson(),
        'pinned': pinned,
        'deleted': deleted,
        'blind_terms': blindTerms,
        if (optInEmbedding != null) 'opt_in_embedding': optInEmbedding,
        if (sourceApp != null) 'source_app': sourceApp,
        'source_device_id': sourceDeviceId,
        'logical_clock': logicalClock,
        'created_at': createdAt.toUtc().toIso8601String(),
        'updated_at': updatedAt.toUtc().toIso8601String(),
      };

  void validate() {
    if (logicalClock < 0) throw ArgumentError.value(logicalClock, 'logicalClock');
    if (updatedAt.isBefore(createdAt)) {
      throw ArgumentError('updatedAt cannot be earlier than createdAt');
    }
    if (payload.nonce.isEmpty || payload.ciphertext.isEmpty || payload.keyId.isEmpty || payload.keyId.length > 128) {
      throw ArgumentError('cipher envelope fields are incomplete or invalid');
    }
    if ((sourceApp?.length ?? 0) > 256) {
      throw ArgumentError('sourceApp may contain at most 256 characters');
    }
    if (blindTerms.length > 256) throw ArgumentError('blindTerms may contain at most 256 entries');
    if (blindTerms.toSet().length != blindTerms.length) {
      throw ArgumentError('blindTerms must not contain duplicates');
    }
    if (blindTerms.any((String term) => term.length < 16 || term.length > 128)) {
      throw ArgumentError('blind terms must contain from 16 through 128 characters');
    }
    if (optInEmbedding != null) {
      if (optInEmbedding!.length != 1536) {
        throw ArgumentError('optInEmbedding must contain exactly 1536 values');
      }
      if (optInEmbedding!.any((double value) => !value.isFinite)) {
        throw ArgumentError('optInEmbedding values must be finite');
      }
    }
  }
}

class SecuritySettings {
  const SecuritySettings({
    required this.reauthIntervalDays,
    required this.reauthMaxDays,
  });

  final int reauthIntervalDays;
  final int reauthMaxDays;

  factory SecuritySettings.fromJson(Map<String, Object?> json) => SecuritySettings(
        reauthIntervalDays: json['reauth_interval_days']! as int,
        reauthMaxDays: json['reauth_max_days']! as int,
      );

  Map<String, Object?> toJson() => <String, Object?>{
        'reauth_interval_days': reauthIntervalDays,
        'reauth_max_days': reauthMaxDays,
      };
}
