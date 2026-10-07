import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;

/// The hash functions ICAO 9303 uses.
enum HashAlgorithm {
  /// SHA-1.
  sha1('1.3.14.3.2.26', 20, 'SHA-1'),

  /// SHA-224.
  sha224('2.16.840.1.101.3.4.2.4', 28, 'SHA-224'),

  /// SHA-256.
  sha256('2.16.840.1.101.3.4.2.1', 32, 'SHA-256'),

  /// SHA-384.
  sha384('2.16.840.1.101.3.4.2.2', 48, 'SHA-384'),

  /// SHA-512.
  sha512('2.16.840.1.101.3.4.2.3', 64, 'SHA-512');

  const HashAlgorithm(this.objectIdentifier, this.length, this.label);

  /// The OBJECT IDENTIFIER of the hash.
  final String objectIdentifier;

  /// The digest length in bytes.
  final int length;

  /// The usual name, such as `SHA-256`.
  final String label;

  /// The hash with [objectIdentifier] [oid], or null.
  static HashAlgorithm? fromObjectIdentifier(String oid) {
    for (final hash in values) {
      if (hash.objectIdentifier == oid) return hash;
    }
    return null;
  }

  /// The digest of [data].
  Uint8List digest(List<int> data) => Uint8List.fromList(
        switch (this) {
          sha1 => crypto.sha1,
          sha224 => crypto.sha224,
          sha256 => crypto.sha256,
          sha384 => crypto.sha384,
          sha512 => crypto.sha512,
        }
            .convert(data)
            .bytes,
      );
}
