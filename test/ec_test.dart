import 'dart:math';

import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/ec.dart';
import 'package:eid_icao/src/crypto/named_parameters.dart';
import 'package:pointycastle/export.dart' show ECDomainParameters;
import 'package:test/test.dart';

void main() {
  final random = Random(7);

  for (final curve in namedCurves.values) {
    group(curve.name, () {
      test('has its base point on the curve, of order n', () {
        expect(curve.contains(curve.generator), isTrue);
        expect(curve.multiplyGenerator(curve.n), isNull);
        expect(
          curve.multiplyGenerator(curve.n - BigInt.one),
          EcPoint(curve.generator.x, curve.p - curve.generator.y),
        );
      });

      test('multiplies as pointycastle does', () {
        final reference = ECDomainParameters(_pointycastleName(curve));
        for (var i = 0; i < 3; i++) {
          final k = randomBelow(curve.n, random);
          final expected = (reference.G * k)!;
          final point = curve.multiplyGenerator(k)!;
          expect(point.x, expected.x!.toBigInteger());
          expect(point.y, expected.y!.toBigInteger());
          final other = curve.multiply(BigInt.from(3), point)!;
          final otherExpected = (expected * BigInt.from(3))!;
          expect(other.x, otherExpected.x!.toBigInteger());
          expect(
            curve.add(point, other),
            curve.multiply(BigInt.from(4), point),
          );
        }
      });

      test('reads its points compressed and uncompressed', () {
        final (_, point) = curve.generateKeyPair(random);
        expect(curve.decode(curve.encode(point)), point);
        final compressed = [
          if (point.y.isOdd) 3 else 2,
          ...bigIntBytes(point.x, curve.size),
        ];
        expect(curve.decode(compressed), point);
        final off = curve.encode(point)..[curve.size] ^= 1;
        expect(() => curve.decode(off), throwsFormatException);
      });
    });
  }

  test('the RFC 5114 groups generate their subgroups', () {
    for (final group in [modp1024, modp2048Q224, modp2048Q256]) {
      expect(group.g.modPow(group.q!, group.p), BigInt.one);
      final (_, public) = group.generateKeyPair(random);
      expect(group.accepts(public), isTrue);
      expect(group.accepts(group.p - BigInt.one), isFalse);
    }
  });
}

String _pointycastleName(EcCurve curve) => switch (curve.name) {
      'NIST P-192' => 'secp192r1',
      'NIST P-224' => 'secp224r1',
      'NIST P-256' => 'secp256r1',
      'NIST P-384' => 'secp384r1',
      'NIST P-521' => 'secp521r1',
      final name => name!.toLowerCase(),
    };
