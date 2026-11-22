import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:cliptown_interfaces/cliptown_interfaces.dart';

void check(bool condition, String context) {
  if (!condition) throw StateError(context);
}

CloudCacheEnvelopeView fromFixture(Map<String, dynamic> row) => CloudCacheEnvelopeView(
      envelopeId: row['envelope_id'] as String,
      serverSequence: row['server_sequence'] as int,
      kind: row['kind'] as String,
      ciphertext: Uint8List(row['ciphertext_bytes'] as int),
    );

void main() {
  final Map<String, dynamic> fixture =
      jsonDecode(File('../../fixtures/cloudflare-text-cache-v1.json').readAsStringSync())
          as Map<String, dynamic>;
  check(fixture['protocol_version'] == 1, 'protocol mismatch');
  final List<dynamic> cases = fixture['cases'] as List<dynamic>;
  for (final dynamic item in cases) {
    final Map<String, dynamic> entry = item as Map<String, dynamic>;
    final String name = entry['name'] as String;
    final List<CloudCacheEnvelopeView> rows =
        (entry['rows'] as List<dynamic>).map((dynamic value) =>
            fromFixture(value as Map<String, dynamic>)).toList(growable: false);
    final String? expectedError = entry['error'] as String?;
    try {
      final CloudCacheRetention actual = planTextCache(rows);
      check(expectedError == null, '$name unexpectedly accepted');
      check(
        actual.retainedIds.join(',') ==
            (entry['retained_ids'] as List<dynamic>).join(','),
        '$name retained mismatch',
      );
      check(
        actual.evictedIds.join(',') ==
            (entry['evicted_ids'] as List<dynamic>).join(','),
        '$name evicted mismatch',
      );
      check(actual.logicalBytes == entry['logical_bytes'], '$name byte mismatch');
    } on CloudCachePolicyError catch (error) {
      check(expectedError == error.code, '$name error mismatch: $error');
    }
  }

  final List<CloudCacheEnvelopeView> items = List<CloudCacheEnvelopeView>.generate(
    2001,
    (int n) => CloudCacheEnvelopeView(
      envelopeId: 'clip_$n', serverSequence: n + 1,
      kind: 'text', ciphertext: Uint8List(1),
    ),
  );
  final CloudCacheRetention cap = planTextCache(items);
  check(cap.retainedIds.length == maxCloudTextItems, 'item cap mismatch');
  check(cap.evictedIds.length == 1 && cap.evictedIds.single == 'clip_0', 'evicted mismatch');

  stdout.writeln('PASS: Dart compiled cache parity (' + cases.length.toString() + ' shared vectors + cap)');
}
