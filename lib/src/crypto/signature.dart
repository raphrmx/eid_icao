import 'dart:typed_data';

import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/hash.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/tlv.dart';

/// Checks [signature] of [data] by [key] under the AlgorithmIdentifier
/// [algorithm]: RSA PKCS #1 v1.5, RSASSA-PSS, or ECDSA with a DER or plain
/// signature.
///
/// Algorithms naming no hash, such as rsaEncryption, use [defaultHash].
/// Returns false when the signature does not hold or the algorithm does not
/// fit [key], and throws a [FormatException] when it is not supported.
bool verifySignature(
  PublicKey key,
  Tlv algorithm,
  List<int> data,
  List<int> signature, {
  HashAlgorithm? defaultHash,
}) =>
    parseUntrusted(
      () => _verifySignature(
        key,
        algorithm,
        data,
        signature,
        defaultHash: defaultHash,
      ),
    );

bool _verifySignature(
  PublicKey key,
  Tlv algorithm,
  List<int> data,
  List<int> signature, {
  HashAlgorithm? defaultHash,
}) {
  final fields = algorithm.children;
  if (fields.isEmpty) throw const FormatException('No signature algorithm');
  final oid = fields[0].objectIdentifier;
  HashAlgorithm hashOr(HashAlgorithm? hash) =>
      hash ??
      defaultHash ??
      (throw FormatException('No hash for signature algorithm $oid'));

  if (oid == '1.2.840.113549.1.1.10') {
    if (key is! RsaPublicKey) return false;
    final (hash, mgfHash) =
        _pssParameters(fields.length > 1 ? fields[1] : null);
    return verifyRsaPss(key, hash, mgfHash, data, signature);
  }
  if (_rsaHashes.containsKey(oid)) {
    if (key is! RsaPublicKey) return false;
    return verifyRsaPkcs1(key, hashOr(_rsaHashes[oid]), data, signature);
  }
  if (_ecdsaHashes.containsKey(oid) || _plainEcdsaHashes.containsKey(oid)) {
    if (key is! EcPublicKey) return false;
    final plain = _plainEcdsaHashes.containsKey(oid);
    final hash = hashOr(_ecdsaHashes[oid] ?? _plainEcdsaHashes[oid]);
    final rs =
        plain ? _plainSignature(key, signature) : _derSignature(signature);
    if (rs == null) return false;
    return verifyEcdsa(key, hash.digest(data), rs.$1, rs.$2);
  }
  throw FormatException('Unsupported signature algorithm $oid');
}

/// The ECDSA (r, s) in [signature], DER or plain r and s one after the
/// other, or null when it is neither.
(BigInt, BigInt)? ecdsaSignature(EcPublicKey key, List<int> signature) =>
    _derSignature(signature) ?? _plainSignature(key, signature);

(BigInt, BigInt)? _derSignature(List<int> signature) {
  try {
    final sequence = Tlv.parse(Uint8List.fromList(signature));
    final values = sequence.children;
    if (sequence.tag != 0x30 ||
        values.length != 2 ||
        sequence.encoded.length != signature.length) {
      return null;
    }
    return (values[0].integer, values[1].integer);
  } on FormatException {
    return null;
  }
}

(BigInt, BigInt)? _plainSignature(EcPublicKey key, List<int> signature) {
  if (signature.length.isOdd || signature.isEmpty) return null;
  final half = signature.length ~/ 2;
  return (
    unsignedBigInt(signature.sublist(0, half)),
    unsignedBigInt(signature.sublist(half)),
  );
}

/// Whether ([r], [s]) is the ECDSA signature of [digest] by [key].
bool verifyEcdsa(EcPublicKey key, List<int> digest, BigInt r, BigInt s) {
  final curve = key.curve;
  final n = curve.n;
  if (r <= BigInt.zero || r >= n || s <= BigInt.zero || s >= n) return false;
  final e = _truncatedDigest(digest, n);
  final w = s.modInverse(n);
  final first = curve.multiplyGenerator(e * w % n);
  final second = curve.multiply(r * w % n, key.point);
  final point = first == null
      ? second
      : second == null
          ? first
          : curve.add(first, second);
  if (point == null) return false;
  return point.x % n == r;
}

/// The ECDSA signature (r, s) of [digest] by the private key [d] on the
/// curve of [key], with a random nonce.
(BigInt, BigInt) signEcdsa(EcPublicKey key, BigInt d, List<int> digest) {
  final curve = key.curve;
  final n = curve.n;
  final e = _truncatedDigest(digest, n);
  while (true) {
    final (k, point) = curve.generateKeyPair();
    final r = point.x % n;
    if (r == BigInt.zero) continue;
    final s = k.modInverse(n) * (e + r * d) % n;
    if (s != BigInt.zero) return (r, s);
  }
}

// The leftmost bits of [digest], as many as n has.
BigInt _truncatedDigest(List<int> digest, BigInt n) {
  var e = unsignedBigInt(digest);
  final excess = digest.length * 8 - n.bitLength;
  if (excess > 0) e >>= excess;
  return e;
}

/// [signature] raised to the public exponent: the encoded message, on the
/// modulus length, or null when [signature] is out of range.
Uint8List? rsaOpen(RsaPublicKey key, List<int> signature) {
  if (signature.length > key.size) return null;
  final s = unsignedBigInt(signature);
  if (s >= key.modulus) return null;
  return bigIntBytes(s.modPow(key.exponent, key.modulus), key.size);
}

/// [message] raised to the private exponent [d]: the raw RSA signature.
Uint8List rsaSeal(RsaPublicKey key, BigInt d, List<int> message) =>
    bigIntBytes(unsignedBigInt(message).modPow(d, key.modulus), key.size);

/// The PKCS #1 v1.5 encoding of the [hash] of [data] for [key].
Uint8List pkcs1Encoding(RsaPublicKey key, HashAlgorithm hash, List<int> data) {
  final info = derSequence([
    derSequence([derObjectIdentifier(hash.objectIdentifier), derNull]),
    derOctetString(hash.digest(data)),
  ]);
  final padding = key.size - info.length - 3;
  if (padding < 8) throw const FormatException('RSA key too short');
  return concat([
    const [0x00, 0x01],
    List.filled(padding, 0xFF),
    const [0x00],
    info,
  ]);
}

/// Whether [signature] is the PKCS #1 v1.5 signature of [data] with [hash].
/// The DigestInfo may carry NULL parameters or none.
bool verifyRsaPkcs1(
  RsaPublicKey key,
  HashAlgorithm hash,
  List<int> data,
  List<int> signature,
) {
  final opened = rsaOpen(key, signature);
  if (opened == null) return false;
  final expected = pkcs1Encoding(key, hash, data);
  if (sameBytes(opened, expected)) return true;
  // The same without the NULL parameters: two bytes fewer in the
  // DigestInfo, two more of padding.
  final info = derSequence([
    derSequence([derObjectIdentifier(hash.objectIdentifier)]),
    derOctetString(hash.digest(data)),
  ]);
  final padding = key.size - info.length - 3;
  return sameBytes(
    opened,
    concat([
      const [0x00, 0x01],
      List.filled(padding, 0xFF),
      const [0x00],
      info,
    ]),
  );
}

/// Whether [signature] is the RSASSA-PSS signature of [data], RFC 8017,
/// with [hash] and MGF1 over [mgfHash]. Any salt length is accepted.
bool verifyRsaPss(
  RsaPublicKey key,
  HashAlgorithm hash,
  HashAlgorithm mgfHash,
  List<int> data,
  List<int> signature,
) {
  final opened = rsaOpen(key, signature);
  if (opened == null) return false;
  final emBits = key.modulus.bitLength - 1;
  final emLength = (emBits + 7) >> 3;
  // When emBits is a multiple of 8 the opened message has a leading zero.
  if (opened.length > emLength && opened[0] != 0) return false;
  final em = opened.sublist(opened.length - emLength);
  final hLength = hash.length;
  if (emLength < hLength + 2 || em.last != 0xBC) return false;
  final maskedDb = em.sublist(0, emLength - hLength - 1);
  final h = em.sublist(emLength - hLength - 1, emLength - 1);
  final unusedBits = 8 * emLength - emBits;
  final topMask = 0xFF >> unusedBits;
  if (maskedDb[0] & ~topMask & 0xFF != 0) return false;
  final db = xorBytes(maskedDb, mgf1(mgfHash, h, maskedDb.length));
  db[0] &= topMask;
  var separator = 0;
  while (separator < db.length && db[separator] == 0) {
    separator++;
  }
  if (separator == db.length || db[separator] != 0x01) return false;
  final salt = db.sublist(separator + 1);
  final expected = hash.digest(concat([
    Uint8List(8),
    hash.digest(data),
    salt,
  ]));
  return sameBytes(expected, h);
}

/// MGF1 of RFC 8017: [length] bytes from [seed].
Uint8List mgf1(HashAlgorithm hash, List<int> seed, int length) {
  final out = BytesBuilder(copy: false);
  for (var counter = 0; out.length < length; counter++) {
    out.add(hash.digest(concat([
      seed,
      [
        counter >> 24 & 0xFF,
        counter >> 16 & 0xFF,
        counter >> 8 & 0xFF,
        counter & 0xFF
      ],
    ])));
  }
  return Uint8List.sublistView(out.takeBytes(), 0, length);
}

(HashAlgorithm, HashAlgorithm) _pssParameters(Tlv? parameters) {
  var hash = HashAlgorithm.sha1;
  var mgfHash = HashAlgorithm.sha1;
  if (parameters == null || parameters.tag != 0x30) return (hash, mgfHash);
  HashAlgorithm hashOf(Tlv algorithm) {
    final oid = algorithm.children.first.objectIdentifier;
    return HashAlgorithm.fromObjectIdentifier(oid) ??
        (throw FormatException('Unsupported PSS hash $oid'));
  }

  for (final field in parameters.children) {
    final content = field.children;
    if (content.isEmpty) continue;
    if (field.tag == 0xA0) hash = hashOf(content.first);
    if (field.tag == 0xA1) {
      final mgf = content.first.children;
      if (mgf.length > 1) mgfHash = hashOf(mgf[1]);
    }
  }
  return (hash, mgfHash);
}

const _rsaHashes = {
  '1.2.840.113549.1.1.1': null,
  '1.2.840.113549.1.1.5': HashAlgorithm.sha1,
  '1.2.840.113549.1.1.14': HashAlgorithm.sha224,
  '1.2.840.113549.1.1.11': HashAlgorithm.sha256,
  '1.2.840.113549.1.1.12': HashAlgorithm.sha384,
  '1.2.840.113549.1.1.13': HashAlgorithm.sha512,
};

const _ecdsaHashes = {
  '1.2.840.10045.2.1': null,
  '1.2.840.10045.4.1': HashAlgorithm.sha1,
  '1.2.840.10045.4.3.1': HashAlgorithm.sha224,
  '1.2.840.10045.4.3.2': HashAlgorithm.sha256,
  '1.2.840.10045.4.3.3': HashAlgorithm.sha384,
  '1.2.840.10045.4.3.4': HashAlgorithm.sha512,
};

// BSI TR-03111 plain signatures: r and s one after the other.
const _plainEcdsaHashes = {
  '0.4.0.127.0.7.1.1.4.1.1': HashAlgorithm.sha1,
  '0.4.0.127.0.7.1.1.4.1.2': HashAlgorithm.sha224,
  '0.4.0.127.0.7.1.1.4.1.3': HashAlgorithm.sha256,
  '0.4.0.127.0.7.1.1.4.1.4': HashAlgorithm.sha384,
  '0.4.0.127.0.7.1.1.4.1.5': HashAlgorithm.sha512,
};

/// The hash of a plain ECDSA algorithm, for Active Authentication.
HashAlgorithm? plainEcdsaHash(String oid) =>
    _plainEcdsaHashes[oid] ?? _ecdsaHashes[oid];
