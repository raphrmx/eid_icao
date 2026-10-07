import 'dart:math';
import 'dart:typed_data';

import 'package:eid_icao/src/bytes.dart';

/// A Diffie-Hellman group: the prime [p], the generator [g] and the order
/// [q] of the subgroup it generates.
final class DhGroup {
  /// A group from its parameters.
  DhGroup({required this.p, required this.g, this.q, this.name})
      : size = byteLength(p);

  /// The prime modulus.
  final BigInt p;

  /// The generator.
  final BigInt g;

  /// The order of [g], when known.
  final BigInt? q;

  /// A name, for a standardized group.
  final String? name;

  /// The bytes of a public key.
  final int size;

  /// Whether [other] has the same parameters.
  bool sameAs(DhGroup other) =>
      identical(this, other) || other.p == p && other.g == g;

  /// Whether [key] is a valid public key: in 2 to p - 2 and, when [q] is
  /// known, in the subgroup.
  bool accepts(BigInt key) {
    if (key <= BigInt.one || key >= p - BigInt.one) return false;
    final order = q;
    return order == null || key.modPow(order, p) == BigInt.one;
  }

  /// [key] on [size] bytes.
  Uint8List encode(BigInt key) => bigIntBytes(key, size);

  /// A key pair: a private exponent and the public key it gives.
  (BigInt, BigInt) generateKeyPair([Random? random]) {
    final private = randomBelow(q ?? p - BigInt.one, random);
    return (private, g.modPow(private, p));
  }

  @override
  String toString() => 'DhGroup(${name ?? '${p.bitLength} bits'})';
}
