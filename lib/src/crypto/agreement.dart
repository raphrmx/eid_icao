import 'dart:math';
import 'dart:typed_data';

import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/dh.dart';
import 'package:eid_icao/src/crypto/ec.dart';
import 'package:eid_icao/src/tlv.dart';

/// Key agreement over an elliptic curve or a Diffie-Hellman group, as PACE
/// and Chip Authentication run it.
sealed class Agreement {
  const Agreement();

  /// The agreement over [parameters], an [EcCurve] or a [DhGroup].
  factory Agreement.over(Object parameters) => switch (parameters) {
        final EcCurve curve => EcAgreement(curve),
        final DhGroup group => DhAgreement(group),
        _ => throw ArgumentError.value(parameters, 'parameters'),
      };

  /// The tag of the public key in a public key data object: 86 for a
  /// point, 84 for a DH value.
  int get publicKeyTag;

  /// A key pair: the private number and the encoded public key.
  (BigInt, Uint8List) generateKeyPair([Random? random]);

  /// The public key of [private], encoded.
  Uint8List publicKey(BigInt private);

  /// The shared secret of [private] and the encoded [peer] key: the x
  /// coordinate of the point, or the DH value, on the field size.
  ///
  /// Throws a [FormatException] when [peer] is not a valid key.
  Uint8List sharedSecret(BigInt private, List<int> peer);

  /// The agreement over the generator the PACE generic mapping gives:
  /// [nonce] times the generator, plus the shared point (or the DH value
  /// times the generator to the [nonce]).
  Agreement mapGeneric(BigInt nonce, BigInt private, List<int> peer);

  /// The public key data object of PACE authentication tokens: 7F49 with
  /// the protocol [oid] and the encoded [key].
  Uint8List publicKeyDataObject(String oid, List<int> key) => tlv(
        0x7F49,
        concat([derObjectIdentifier(oid), tlv(publicKeyTag, key)]),
      );
}

/// ECDH over [curve].
final class EcAgreement extends Agreement {
  /// ECDH over [curve].
  const EcAgreement(this.curve);

  /// The curve.
  final EcCurve curve;

  @override
  int get publicKeyTag => 0x86;

  @override
  (BigInt, Uint8List) generateKeyPair([Random? random]) {
    final (private, point) = curve.generateKeyPair(random);
    return (private, curve.encode(point));
  }

  @override
  Uint8List publicKey(BigInt private) =>
      curve.encode(curve.multiplyGenerator(private)!);

  @override
  Uint8List sharedSecret(BigInt private, List<int> peer) =>
      bigIntBytes(_shared(private, peer).x, curve.size);

  EcPoint _shared(BigInt private, List<int> peer) {
    final point = curve.decode(peer);
    final shared = curve.multiply(private * curve.h, point);
    if (shared == null) throw const FormatException('Degenerate key');
    return shared;
  }

  @override
  Agreement mapGeneric(BigInt nonce, BigInt private, List<int> peer) {
    final h = _shared(private, peer);
    final s = curve.multiplyGenerator(nonce % curve.n);
    final g = s == null ? h : curve.add(s, h);
    if (g == null) throw const FormatException('Degenerate mapping');
    return EcAgreement(EcCurve(
      p: curve.p,
      a: curve.a,
      b: curve.b,
      gx: g.x,
      gy: g.y,
      n: curve.n,
      h: curve.h,
    ));
  }
}

/// Diffie-Hellman in [group].
final class DhAgreement extends Agreement {
  /// Diffie-Hellman in [group].
  const DhAgreement(this.group);

  /// The group.
  final DhGroup group;

  @override
  int get publicKeyTag => 0x84;

  @override
  (BigInt, Uint8List) generateKeyPair([Random? random]) {
    final (private, public) = group.generateKeyPair(random);
    return (private, group.encode(public));
  }

  @override
  Uint8List publicKey(BigInt private) =>
      group.encode(group.g.modPow(private, group.p));

  @override
  Uint8List sharedSecret(BigInt private, List<int> peer) =>
      group.encode(_shared(private, peer));

  BigInt _shared(BigInt private, List<int> peer) {
    final y = unsignedBigInt(peer);
    if (!group.accepts(y)) throw const FormatException('Invalid DH key');
    return y.modPow(private, group.p);
  }

  @override
  Agreement mapGeneric(BigInt nonce, BigInt private, List<int> peer) {
    final h = _shared(private, peer);
    final g = group.g.modPow(nonce, group.p) * h % group.p;
    if (g <= BigInt.one) throw const FormatException('Degenerate mapping');
    return DhAgreement(DhGroup(p: group.p, g: g, q: group.q));
  }
}
