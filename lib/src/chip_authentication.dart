import 'dart:typed_data';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/agreement.dart';
import 'package:eid_icao/src/crypto/cipher.dart';
import 'package:eid_icao/src/crypto/hash.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/crypto/signature.dart';
import 'package:eid_icao/src/secure_messaging.dart';
import 'package:eid_icao/src/security_infos.dart';
import 'package:eid_icao/src/tlv.dart';

/// The Chip Authentication variant and key to run from [infos], DG14, or
/// null when it offers none this package supports.
(ChipAuthenticationInfo, ChipAuthenticationPublicKey)? chipAuthenticationOf(
  SecurityInfos infos,
) {
  for (final info in infos.chipAuthentication) {
    if (info.cipher == null) continue;
    for (final key in infos.chipAuthenticationKeys) {
      if (info.keyId != null && key.keyId != null && info.keyId != key.keyId) {
        continue;
      }
      if (key.publicKey is EcPublicKey || key.publicKey is DhPublicKey) {
        return (info, key);
      }
    }
  }
  return null;
}

/// Runs Chip Authentication, ICAO 9303 part 11, over the current secure
/// messaging [channel], and returns the session under the new keys.
///
/// The chip proves it holds the private key of [key] by answering under
/// those keys: a session that then fails means a cloned chip. Throws a
/// [CardException] when the chip refuses the protocol.
Future<SecureMessaging> performChipAuthentication(
  CardChannel channel,
  CardChannel raw,
  ChipAuthenticationInfo info,
  ChipAuthenticationPublicKey key, {
  BigInt? ephemeralKey,
}) async {
  final cipher = info.cipher!;
  final (agreement, chipKey) = switch (key.publicKey) {
    EcPublicKey(:final curve, :final point) => (
        EcAgreement(curve) as Agreement,
        curve.encode(point),
      ),
    DhPublicKey(:final group, :final y) => (
        DhAgreement(group) as Agreement,
        group.encode(y),
      ),
    _ => throw ArgumentError.value(key, 'key'),
  };
  final (private, public) = ephemeralKey == null
      ? agreement.generateKeyPair()
      : (ephemeralKey, agreement.publicKey(ephemeralKey));
  final keyReference = [
    if (key.keyId ?? info.keyId case final id?) ...tlv(0x84, _minimal(id)),
  ];

  if (cipher == SymmetricCipher.tripleDes) {
    // Version 1: MSE:Set KAT carries the key.
    await channel.expect(
      CommandApdu(0x00, 0x22, 0x41, 0xA6,
          data: concat([tlv(0x91, public), keyReference])),
      'MSE:SET KAT',
    );
  } else {
    await channel.expect(
      CommandApdu(0x00, 0x22, 0x41, 0xA4,
          data: concat([
            tlv(0x80, encodeObjectIdentifier(info.objectIdentifier)),
            keyReference,
          ])),
      'MSE:SET AT',
    );
    await channel.expect(
      CommandApdu(0x00, 0x86, 0x00, 0x00,
          data: tlv(0x7C, tlv(0x80, public)), le: 32),
      'GENERAL AUTHENTICATE',
    );
  }

  final secret = agreement.sharedSecret(private, chipKey);
  return SecureMessaging.fromZero(
    raw,
    cipher: cipher,
    encryptionKey: cipher.deriveKey(secret, 1),
    macKey: cipher.deriveKey(secret, 2),
  );
}

List<int> _minimal(int value) {
  final bytes = <int>[];
  var rest = value;
  do {
    bytes.insert(0, rest & 0xFF);
    rest >>= 8;
  } while (rest > 0);
  return bytes;
}

/// Runs Active Authentication, ICAO 9303 part 11: the chip signs a random
/// [challenge] with the private key of [key], from DG15.
///
/// [ecdsaAlgorithm] is the signature algorithm DG14 names for an EC key.
/// Returns whether the signature holds.
Future<bool> performActiveAuthentication(
  CardChannel channel,
  PublicKey key, {
  String? ecdsaAlgorithm,
  Uint8List? challenge,
}) async {
  final nonce = challenge ?? randomBytes(8);
  final signature = await channel.expect(
    CommandApdu(0x00, 0x88, 0x00, 0x00,
        data: nonce,
        // The exact length, so that the protected answer fits a short APDU
        // whenever it can.
        le: switch (key) {
          RsaPublicKey(:final size) => size,
          EcPublicKey(:final curve) => 2 * curve.size + 8,
          DhPublicKey() => 256,
        }),
    'INTERNAL AUTHENTICATE',
  );
  return verifyActiveAuthentication(
    key,
    nonce,
    signature,
    ecdsaAlgorithm: ecdsaAlgorithm,
  );
}

/// Whether [signature] is the Active Authentication answer of [key] to
/// [challenge]: ISO 9796-2 scheme 1 for RSA, ECDSA otherwise.
bool verifyActiveAuthentication(
  PublicKey key,
  List<int> challenge,
  List<int> signature, {
  String? ecdsaAlgorithm,
}) {
  switch (key) {
    case final RsaPublicKey rsa:
      final opened = rsaOpen(rsa, signature);
      if (opened == null) return false;
      // ISO 9796-2 allows the signer to send n - s: try both.
      return _iso9796Holds(opened, challenge) ||
          _iso9796Holds(
            bigIntBytes(rsa.modulus - unsignedBigInt(opened), rsa.size),
            challenge,
          );
    case final EcPublicKey ec:
      final hash =
          (ecdsaAlgorithm == null ? null : plainEcdsaHash(ecdsaAlgorithm)) ??
              _hashForCurve(ec);
      final rs = ecdsaSignature(ec, signature);
      if (rs == null) return false;
      return verifyEcdsa(ec, hash.digest(challenge), rs.$1, rs.$2);
    case DhPublicKey():
      return false;
  }
}

HashAlgorithm _hashForCurve(EcPublicKey key) {
  final bits = key.curve.n.bitLength;
  if (bits <= 160) return HashAlgorithm.sha1;
  if (bits <= 224) return HashAlgorithm.sha224;
  if (bits <= 256) return HashAlgorithm.sha256;
  if (bits <= 384) return HashAlgorithm.sha384;
  return HashAlgorithm.sha512;
}

// ISO/IEC 9796-2 digital signature scheme 1, partial or total recovery:
// header, recoverable message M1, hash of M1 || M2, trailer.
bool _iso9796Holds(Uint8List f, List<int> m2) {
  if (f.length < 24 || f[0] & 0xC0 != 0x40) return false;
  HashAlgorithm? hash;
  var trailer = 1;
  if (f.last == 0xBC) {
    hash = HashAlgorithm.sha1;
  } else if (f.last == 0xCC) {
    trailer = 2;
    hash = switch (f[f.length - 2]) {
      0x33 => HashAlgorithm.sha1,
      0x34 => HashAlgorithm.sha256,
      0x35 => HashAlgorithm.sha512,
      0x36 => HashAlgorithm.sha384,
      0x38 => HashAlgorithm.sha224,
      _ => null,
    };
  }
  if (hash == null) return false;
  final digestEnd = f.length - trailer;
  final digestStart = digestEnd - hash.length;
  if (digestStart < 1) return false;
  // The recovered message starts after the first byte ending in nibble A:
  // the header 6A, or the padding BB...BA of a total recovery.
  var start = 0;
  while (start < digestStart && f[start] & 0x0F != 0x0A) {
    start++;
  }
  start++;
  if (start > digestStart) return false;
  final m1 = f.sublist(start, digestStart);
  return sameBytes(
    hash.digest(concat([m1, m2])),
    f.sublist(digestStart, digestEnd),
  );
}
