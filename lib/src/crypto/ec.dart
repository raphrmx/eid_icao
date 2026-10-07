import 'dart:math';
import 'dart:typed_data';

import 'package:eid_icao/src/bytes.dart';

/// A point of an elliptic curve, in affine coordinates.
final class EcPoint {
  /// The point ([x], [y]).
  const EcPoint(this.x, this.y);

  /// The x coordinate.
  final BigInt x;

  /// The y coordinate.
  final BigInt y;

  @override
  bool operator ==(Object other) =>
      other is EcPoint && other.x == x && other.y == y;

  @override
  int get hashCode => Object.hash(x, y);

  @override
  String toString() => 'EcPoint(${x.toRadixString(16)}, '
      '${y.toRadixString(16)})';
}

/// A curve y² = x³ + ax + b over the prime field of [p], with the base
/// point ([gx], [gy]) of order [n] and cofactor [h].
///
/// Arithmetic runs in Jacobian coordinates. It is not constant time: it
/// serves signature checks and the terminal's ephemeral keys.
final class EcCurve {
  /// A curve from its domain parameters.
  EcCurve({
    required this.p,
    required this.a,
    required this.b,
    required BigInt gx,
    required BigInt gy,
    required this.n,
    BigInt? h,
    this.name,
    this.objectIdentifier,
  })  : h = h ?? BigInt.one,
        generator = EcPoint(gx, gy),
        size = byteLength(p);

  /// The field prime.
  final BigInt p;

  /// The coefficient a.
  final BigInt a;

  /// The coefficient b.
  final BigInt b;

  /// The base point.
  final EcPoint generator;

  /// The order of [generator].
  final BigInt n;

  /// The cofactor.
  final BigInt h;

  /// A name such as `brainpoolP256r1`, for a named curve.
  final String? name;

  /// The OBJECT IDENTIFIER of a named curve.
  final String? objectIdentifier;

  /// The bytes of a coordinate.
  final int size;

  late final List<EcPoint> _generatorTable = _multiples(generator);

  /// Whether [other] has the same domain parameters.
  bool sameAs(EcCurve other) =>
      identical(this, other) ||
      other.p == p &&
          other.a % p == a % p &&
          other.b == b &&
          other.generator == generator &&
          other.n == n;

  /// Whether [point] lies on the curve.
  bool contains(EcPoint point) {
    final x = point.x;
    final y = point.y;
    if (x.isNegative || x >= p || y.isNegative || y >= p) return false;
    return (y * y - (x * x * x + a * x + b)) % p == BigInt.zero;
  }

  /// [k] times [point], or null for the point at infinity.
  EcPoint? multiply(BigInt k, EcPoint point) => _toAffine(
        _multiply(
          k,
          identical(point, generator) || point == generator
              ? _generatorTable
              : _multiples(point),
        ),
      );

  /// [k] times the base point, or null for the point at infinity.
  EcPoint? multiplyGenerator(BigInt k) =>
      _toAffine(_multiply(k, _generatorTable));

  /// The sum of [first] and [second], or null for the point at infinity.
  EcPoint? add(EcPoint first, EcPoint second) =>
      _toAffine(_addAffine((first.x, first.y, BigInt.one), second.x, second.y));

  /// [point] as an uncompressed octet string: 04, then x and y.
  Uint8List encode(EcPoint point) => concat([
        const [0x04],
        bigIntBytes(point.x, size),
        bigIntBytes(point.y, size),
      ]);

  /// Reads a point, uncompressed or compressed, and checks it lies on the
  /// curve. Throws a [FormatException] otherwise.
  EcPoint decode(List<int> bytes) {
    if (bytes.isEmpty) throw const FormatException('Empty point');
    final EcPoint point;
    if (bytes[0] == 0x04 && bytes.length == 1 + 2 * size) {
      point = EcPoint(
        unsignedBigInt(bytes.sublist(1, 1 + size)),
        unsignedBigInt(bytes.sublist(1 + size)),
      );
    } else if ((bytes[0] == 0x02 || bytes[0] == 0x03) &&
        bytes.length == 1 + size) {
      final x = unsignedBigInt(bytes.sublist(1));
      final y = _squareRoot((x * x * x + a * x + b) % p);
      if (y == null) throw const FormatException('Not a point of the curve');
      final odd = bytes[0] == 0x03;
      point = EcPoint(x, y.isOdd == odd ? y : (p - y) % p);
    } else {
      throw const FormatException('Malformed point');
    }
    if (!contains(point)) {
      throw const FormatException('Not a point of the curve');
    }
    return point;
  }

  /// A key pair: a private number and the point it gives.
  (BigInt, EcPoint) generateKeyPair([Random? random]) {
    while (true) {
      final private = randomBelow(n, random);
      final public = multiplyGenerator(private);
      if (public != null) return (private, public);
    }
  }

  @override
  String toString() => 'EcCurve(${name ?? '${p.bitLength} bits'})';

  // A point in Jacobian coordinates: (X / Z², Y / Z³). Z = 0 is infinity.
  static final _infinity = (BigInt.one, BigInt.one, BigInt.zero);
  static final _three = BigInt.from(3);
  static final _four = BigInt.from(4);
  static final _eight = BigInt.from(8);
  static final _fifteen = BigInt.from(15);
  static final _searchLimit = BigInt.from(1000);

  EcPoint? _toAffine(_Point point) {
    final (x, y, z) = point;
    if (z == BigInt.zero) return null;
    final zInverse = z.modInverse(p);
    final zz = zInverse * zInverse % p;
    return EcPoint(x * zz % p, y * zz % p * zInverse % p);
  }

  // 1 to 15 times [point], in affine coordinates, for [_multiply].
  List<EcPoint> _multiples(EcPoint point) {
    final points = <_Point>[];
    final base = (point.x, point.y, BigInt.one);
    var multiple = base;
    for (var j = 1; j <= 15; j++) {
      points.add(multiple);
      multiple = _addAffine(multiple, point.x, point.y);
    }
    return _batchAffine(points);
  }

  // k times the point whose [_multiples] are [table], four bits at a time.
  _Point _multiply(BigInt k, List<EcPoint> table) {
    if (k.isNegative) throw ArgumentError.value(k, 'k', 'Negative scalar');
    var result = _infinity;
    for (var shift = (k.bitLength + 3) & ~3; shift > 0;) {
      shift -= 4;
      result = _double(_double(_double(_double(result))));
      // BigInt.toInt clamps: mask before converting.
      final digit = ((k >> shift) & _fifteen).toInt();
      if (digit != 0) {
        final multiple = table[digit - 1];
        result = _addAffine(result, multiple.x, multiple.y);
      }
    }
    return result;
  }

  // dbl-2007-bl, for any a.
  _Point _double(_Point point) {
    final (x, y, z) = point;
    if (z == BigInt.zero || y == BigInt.zero) return _infinity;
    final xx = x * x % p;
    final yy = y * y % p;
    final yyyy = yy * yy % p;
    final zz = z * z % p;
    final s = BigInt.two * ((x + yy) * (x + yy) - xx - yyyy) % p;
    final m = (_three * xx + a * (zz * zz % p)) % p;
    final x3 = (m * m - BigInt.two * s) % p;
    final y3 = (m * (s - x3) - _eight * yyyy) % p;
    final z3 = ((y + z) * (y + z) - yy - zz) % p;
    return (x3, y3, z3);
  }

  // madd-2007-bl: adds the affine point (x2, y2).
  _Point _addAffine(_Point point, BigInt x2, BigInt y2) {
    final (x1, y1, z1) = point;
    if (z1 == BigInt.zero) return (x2, y2, BigInt.one);
    final z1z1 = z1 * z1 % p;
    final u2 = x2 * z1z1 % p;
    final s2 = y2 * z1 % p * z1z1 % p;
    final diff = (u2 - x1) % p;
    final r = BigInt.two * (s2 - y1) % p;
    if (diff == BigInt.zero) {
      return r == BigInt.zero ? _double(point) : _infinity;
    }
    final hh = diff * diff % p;
    final i = _four * hh % p;
    final j = diff * i % p;
    final v = x1 * i % p;
    final x3 = (r * r - j - BigInt.two * v) % p;
    final y3 = (r * (v - x3) - BigInt.two * y1 * j) % p;
    final z3 = ((z1 + diff) * (z1 + diff) - z1z1 - hh) % p;
    return (x3, y3, z3);
  }

  // Many points to affine coordinates with one inversion (Montgomery's
  // trick). None may be at infinity.
  List<EcPoint> _batchAffine(List<_Point> points) {
    final prefix = <BigInt>[];
    var product = BigInt.one;
    for (final (_, _, z) in points) {
      prefix.add(product);
      product = product * z % p;
    }
    if (product == BigInt.zero) {
      // A small multiple hit infinity: only on a point of tiny order.
      throw const FormatException('Point of small order');
    }
    var inverse = product.modInverse(p);
    final result = List.filled(points.length, generator);
    for (var i = points.length - 1; i >= 0; i--) {
      final (x, y, z) = points[i];
      final zInverse = inverse * prefix[i] % p;
      inverse = inverse * z % p;
      final zz = zInverse * zInverse % p;
      result[i] = EcPoint(x * zz % p, y * zz % p * zInverse % p);
    }
    return result;
  }

  // A square root of [value] modulo p, or null (Tonelli-Shanks).
  BigInt? _squareRoot(BigInt value) {
    if (value == BigInt.zero) return BigInt.zero;
    final one = BigInt.one;
    final pMinusOne = p - one;
    if (value.modPow(pMinusOne >> 1, p) != one) return null;
    if (p % _four == _three) return value.modPow((p + one) >> 2, p);
    var q = pMinusOne;
    var s = 0;
    while (q.isEven) {
      q >>= 1;
      s++;
    }
    // A prime has a non-residue among its first values; give up otherwise.
    var z = BigInt.two;
    while (z.modPow(pMinusOne >> 1, p) != pMinusOne) {
      z += one;
      if (z > _searchLimit) return null;
    }
    var m = s;
    var c = z.modPow(q, p);
    var t = value.modPow(q, p);
    var r = value.modPow((q + one) >> 1, p);
    while (t != one) {
      var i = 0;
      var t2 = t;
      while (t2 != one) {
        t2 = t2 * t2 % p;
        if (++i >= m) return null;
      }
      final bb = c.modPow(one << (m - i - 1), p);
      m = i;
      c = bb * bb % p;
      t = t * c % p;
      r = r * bb % p;
    }
    return r;
  }
}

typedef _Point = (BigInt, BigInt, BigInt);

/// Whether [n] is prime, by Miller-Rabin over the first prime bases: wrong
/// with odds far below those of a random key collision.
bool isProbablePrime(BigInt n) {
  const bases = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];
  if (n < BigInt.two) return false;
  for (final base in bases) {
    final b = BigInt.from(base);
    if (n == b) return true;
    if (n % b == BigInt.zero) return false;
  }
  final nMinusOne = n - BigInt.one;
  var d = nMinusOne;
  var r = 0;
  while (d.isEven) {
    d >>= 1;
    r++;
  }
  outer:
  for (final base in bases) {
    var x = BigInt.from(base).modPow(d, n);
    if (x == BigInt.one || x == nMinusOne) continue;
    for (var i = 1; i < r; i++) {
      x = x * x % n;
      if (x == nMinusOne) continue outer;
    }
    return false;
  }
  return true;
}
