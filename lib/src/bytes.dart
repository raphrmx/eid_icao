import 'dart:math';
import 'dart:typed_data';

/// Whether [a] and [b] hold the same bytes, in time independent of where
/// they differ.
bool sameBytes(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var difference = 0;
  for (var i = 0; i < a.length; i++) {
    difference |= a[i] ^ b[i];
  }
  return difference == 0;
}

/// [bytes] read as an unsigned big-endian number.
BigInt unsignedBigInt(List<int> bytes) {
  var value = BigInt.zero;
  for (final byte in bytes) {
    value = value << 8 | BigInt.from(byte);
  }
  return value;
}

final _byte = BigInt.from(0xFF);

/// [value] as [length] unsigned big-endian bytes, its high bytes cut if it
/// does not fit.
Uint8List bigIntBytes(BigInt value, int length) {
  final bytes = Uint8List(length);
  var rest = value;
  for (var i = length - 1; i >= 0; i--) {
    bytes[i] = (rest & _byte).toInt();
    rest >>= 8;
  }
  return bytes;
}

/// The bytes [value] needs, unsigned.
int byteLength(BigInt value) => (value.bitLength + 7) >> 3;

/// [parts] one after the other.
Uint8List concat(List<List<int>> parts) {
  final length = parts.fold(0, (sum, part) => sum + part.length);
  final bytes = Uint8List(length);
  var offset = 0;
  for (final part in parts) {
    bytes.setRange(offset, offset + part.length, part);
    offset += part.length;
  }
  return bytes;
}

/// [a] XOR [b], which have the same length.
Uint8List xorBytes(List<int> a, List<int> b) =>
    Uint8List.fromList([for (var i = 0; i < a.length; i++) a[i] ^ b[i]]);

/// [length] bytes from a cryptographically secure source.
Uint8List randomBytes(int length, [Random? random]) {
  final source = random ?? Random.secure();
  return Uint8List.fromList(
    List.generate(length, (_) => source.nextInt(256)),
  );
}

/// A number from 1 to [limit] - 1, from a cryptographically secure source.
BigInt randomBelow(BigInt limit, [Random? random]) {
  final length = byteLength(limit) + 8;
  final value = unsignedBigInt(randomBytes(length, random));
  return value % (limit - BigInt.one) + BigInt.one;
}

/// Parses [hex], spaces allowed, into bytes.
Uint8List hexBytes(String hex) {
  final clean = hex.replaceAll(RegExp(r'\s'), '');
  if (clean.length.isOdd) throw FormatException('Odd hex length', hex);
  return Uint8List.fromList([
    for (var i = 0; i < clean.length; i += 2)
      int.parse(clean.substring(i, i + 2), radix: 16),
  ]);
}
