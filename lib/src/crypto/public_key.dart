import 'dart:typed_data';

import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/dh.dart';
import 'package:eid_icao/src/crypto/ec.dart';
import 'package:eid_icao/src/crypto/named_parameters.dart';
import 'package:eid_icao/src/tlv.dart';

/// A public key out of a SubjectPublicKeyInfo: RSA, EC or Diffie-Hellman.
sealed class PublicKey {
  const PublicKey();

  /// Reads a DER SubjectPublicKeyInfo.
  ///
  /// EC parameters may be a named curve or explicit, as ICAO certificates
  /// often carry them. Throws a [FormatException] for anything else.
  factory PublicKey.parse(Uint8List info) => PublicKey.fromTlv(Tlv.parse(info));

  /// Reads a SubjectPublicKeyInfo already parsed.
  factory PublicKey.fromTlv(Tlv info) =>
      parseUntrusted(() => PublicKey._fromTlvUnchecked(info));

  factory PublicKey._fromTlvUnchecked(Tlv info) {
    final parts = info.children;
    if (info.tag != 0x30 || parts.length != 2) {
      throw const FormatException('Not a SubjectPublicKeyInfo');
    }
    final algorithm = parts[0].children;
    if (algorithm.isEmpty) throw const FormatException('No key algorithm');
    final key = parts[1].bitString;
    final parameters = algorithm.length > 1 ? algorithm[1] : null;
    switch (algorithm[0].objectIdentifier) {
      case '1.2.840.113549.1.1.1':
      case '1.2.840.113549.1.1.10':
        final numbers = Tlv.parse(key).children;
        if (numbers.length < 2) throw const FormatException('Not an RSA key');
        return RsaPublicKey(numbers[0].integer, numbers[1].integer);
      case '1.2.840.10045.2.1':
        if (parameters == null) {
          throw const FormatException('EC key without parameters');
        }
        final curve = ecParameters(parameters);
        return EcPublicKey(curve, curve.decode(key));
      case '1.2.840.10046.2.1':
      case '1.2.840.113549.1.3.1':
        if (parameters == null) {
          throw const FormatException('DH key without parameters');
        }
        final group = dhParameters(parameters);
        final y = Tlv.parse(key).integer;
        if (!group.accepts(y)) throw const FormatException('Invalid DH key');
        return DhPublicKey(group, y);
      default:
        throw FormatException(
          'Unsupported key algorithm ${algorithm[0].objectIdentifier}',
        );
    }
  }
}

/// An RSA public key.
final class RsaPublicKey extends PublicKey {
  /// The key of [modulus] and [exponent].
  RsaPublicKey(this.modulus, this.exponent) {
    if (modulus.bitLength < 1024 || exponent <= BigInt.one) {
      throw const FormatException('RSA key too weak');
    }
    if (modulus.bitLength > 8192 || exponent >= modulus) {
      throw const FormatException('RSA key out of range');
    }
  }

  /// The modulus n.
  final BigInt modulus;

  /// The public exponent e.
  final BigInt exponent;

  /// The modulus length in bytes.
  int get size => (modulus.bitLength + 7) >> 3;
}

/// An elliptic curve public key.
final class EcPublicKey extends PublicKey {
  /// The key [point] on [curve].
  const EcPublicKey(this.curve, this.point);

  /// The curve.
  final EcCurve curve;

  /// The public point.
  final EcPoint point;
}

/// A Diffie-Hellman public key.
final class DhPublicKey extends PublicKey {
  /// The key [y] in [group].
  const DhPublicKey(this.group, this.y);

  /// The group.
  final DhGroup group;

  /// The public value.
  final BigInt y;
}

/// The curve [parameters] name or spell out, ECParameters of X9.62.
///
/// Explicit parameters equal to a named curve give that curve.
EcCurve ecParameters(Tlv parameters) {
  if (parameters.tag == 0x06) {
    final oid = parameters.objectIdentifier;
    return namedCurves[oid] ??
        (throw FormatException('Unsupported named curve $oid'));
  }
  final fields = parameters.children;
  if (parameters.tag != 0x30 || fields.length < 5) {
    throw const FormatException('Malformed EC parameters');
  }
  final field = fields[1].children;
  if (field.length != 2 || field[0].objectIdentifier != '1.2.840.10045.1.1') {
    throw const FormatException('Only prime field curves are supported');
  }
  final p = field[1].integer;
  final coefficients = fields[2].children;
  if (coefficients.length < 2) {
    throw const FormatException('Malformed EC parameters');
  }
  final a = unsignedBigInt(coefficients[0].value);
  final b = unsignedBigInt(coefficients[1].value);
  final n = fields[4].integer;
  final h = fields.length > 5 ? fields[5].integer : BigInt.one;
  // Explicit parameters come from the chip before anything vouches for
  // them: refuse those that would be costly or meaningless.
  if (p.bitLength < 160 ||
      p.bitLength > 521 ||
      n.bitLength > p.bitLength + 1 ||
      n < BigInt.two ||
      h < BigInt.one ||
      h.bitLength > 16 ||
      a >= p ||
      b >= p ||
      !isProbablePrime(p) ||
      !isProbablePrime(n)) {
    throw const FormatException('Unsupported EC parameters');
  }
  final base = fields[3].value;
  // Decode the base point on a curve without a base point yet.
  final provisional = EcCurve(
    p: p,
    a: a,
    b: b,
    gx: BigInt.zero,
    gy: BigInt.zero,
    n: n,
    h: h,
  );
  final g = provisional.decode(base);
  final explicit = EcCurve(p: p, a: a, b: b, gx: g.x, gy: g.y, n: n, h: h);
  for (final named in namedCurves.values) {
    if (named.sameAs(explicit)) return named;
  }
  return explicit;
}

/// The group [parameters] spell out: X9.42 DomainParameters (p, g, q) or
/// PKCS #3 DHParameter (p, g).
DhGroup dhParameters(Tlv parameters) {
  final numbers = parameters.children;
  if (parameters.tag != 0x30 || numbers.length < 2) {
    throw const FormatException('Malformed DH parameters');
  }
  final p = numbers[0].integer;
  final g = numbers[1].integer;
  final q =
      numbers.length > 2 && numbers[2].tag == 0x02 ? numbers[2].integer : null;
  for (final group in [modp1024, modp2048Q224, modp2048Q256]) {
    if (group.p == p && group.g == g) return group;
  }
  if (p.bitLength < 1024 ||
      p.bitLength > 4096 ||
      g <= BigInt.one ||
      g >= p ||
      !isProbablePrime(p)) {
    throw const FormatException('Unsupported DH parameters');
  }
  // PKCS #3 puts the private value length third, not q.
  final order = q != null && q.bitLength > 64 ? q : null;
  return DhGroup(p: p, g: g, q: order);
}
