import 'dart:convert';
import 'dart:typed_data';

import 'package:eid_icao/src/bytes.dart';

/// One BER-TLV element: a tag, then the length and value it announces.
///
/// Tags of several bytes, such as `5F1F` or `7F61`, are read whole into
/// [tag]. Lengths may be indefinite on constructed elements.
final class Tlv {
  Tlv._(
    this._bytes,
    this.tag,
    this._start,
    this._valueStart,
    this._valueEnd,
    this._end,
  );

  /// Reads the element at [offset] of [bytes].
  ///
  /// Throws a [FormatException] when it is malformed or runs past the end.
  factory Tlv.parse(Uint8List bytes, [int offset = 0]) {
    var position = offset;
    int next() {
      if (position >= bytes.length) {
        throw FormatException('Truncated TLV element', bytes, offset);
      }
      return bytes[position++];
    }

    final first = next();
    var tag = first;
    if (first & 0x1F == 0x1F) {
      int byte;
      var count = 0;
      do {
        byte = next();
        tag = tag << 8 | byte;
        if (++count > 3) throw FormatException('Tag too long', bytes, offset);
      } while (byte & 0x80 != 0);
    }

    final lengthByte = next();
    if (lengthByte == 0x80) {
      if (first & 0x20 == 0) {
        throw FormatException('Indefinite primitive element', bytes, offset);
      }
      final valueStart = position;
      while (true) {
        if (position + 2 > bytes.length) {
          throw FormatException('Unterminated element', bytes, offset);
        }
        if (bytes[position] == 0 && bytes[position + 1] == 0) {
          return Tlv._(bytes, tag, offset, valueStart, position, position + 2);
        }
        position = Tlv.parse(bytes, position)._end;
      }
    }
    var length = lengthByte;
    if (lengthByte > 0x80) {
      final count = lengthByte & 0x7F;
      if (count > 3) throw FormatException('Length too long', bytes, offset);
      length = 0;
      for (var i = 0; i < count; i++) {
        length = length << 8 | next();
      }
    }
    final end = position + length;
    if (end > bytes.length) {
      throw FormatException('TLV element runs past the end', bytes, offset);
    }
    return Tlv._(bytes, tag, offset, position, end, end);
  }

  /// Reads every element of [bytes], skipping the 00 and FF padding
  /// ISO 7816-4 allows between them.
  static List<Tlv> parseAll(Uint8List bytes) {
    final elements = <Tlv>[];
    var offset = 0;
    while (offset < bytes.length) {
      final byte = bytes[offset];
      if (byte == 0x00 || byte == 0xFF) {
        offset++;
        continue;
      }
      final element = Tlv.parse(bytes, offset);
      elements.add(element);
      offset = element._end;
    }
    return elements;
  }

  /// The size of the element whose first bytes are [start], header
  /// included, or null when more bytes are needed to tell. Throws a
  /// [FormatException] on an indefinite or oversized length.
  static int? encodedSize(List<int> start) {
    var position = 0;
    if (start.isEmpty) return null;
    if (start[0] & 0x1F == 0x1F) {
      do {
        position++;
        if (position >= start.length) return null;
      } while (start[position] & 0x80 != 0);
    }
    position++;
    if (position >= start.length) return null;
    final lengthByte = start[position++];
    if (lengthByte < 0x80) return position + lengthByte;
    final count = lengthByte & 0x7F;
    if (count == 0 || count > 3) {
      throw const FormatException('Unsupported length in a file header');
    }
    if (position + count > start.length) return null;
    var length = 0;
    for (var i = 0; i < count; i++) {
      length = length << 8 | start[position + i];
    }
    return position + count + length;
  }

  final Uint8List _bytes;
  final int _start;
  final int _valueStart;
  final int _valueEnd;
  final int _end;

  /// The tag, its bytes read as one number: `0x30`, `0x5F1F`, `0x7F61`.
  final int tag;

  /// Whether the element holds other elements.
  bool get isConstructed {
    var first = tag;
    while (first > 0xFF) {
      first >>= 8;
    }
    return first & 0x20 != 0;
  }

  /// The element as encoded, header included.
  Uint8List get encoded => Uint8List.sublistView(_bytes, _start, _end);

  /// The value, header excluded.
  Uint8List get value => Uint8List.sublistView(_bytes, _valueStart, _valueEnd);

  /// The elements a constructed element holds.
  List<Tlv> get children {
    final children = <Tlv>[];
    final scope = Uint8List.sublistView(_bytes, 0, _valueEnd);
    var offset = _valueStart;
    while (offset < _valueEnd) {
      final child = Tlv.parse(scope, offset);
      children.add(child);
      offset = child._end;
    }
    return children;
  }

  /// The first child tagged [tag], or null.
  Tlv? child(int tag) {
    for (final element in children) {
      if (element.tag == tag) return element;
    }
    return null;
  }

  /// The first child tagged [tag]. Throws a [FormatException] if missing.
  Tlv require(int tag) =>
      child(tag) ??
      (throw FormatException(
        'Tag ${tag.toRadixString(16).toUpperCase()} missing',
      ));

  /// The value of an INTEGER, signed.
  BigInt get integer {
    final bytes = value;
    if (bytes.isEmpty) throw const FormatException('Empty INTEGER');
    final magnitude = unsignedBigInt(bytes);
    return bytes[0] & 0x80 == 0
        ? magnitude
        : magnitude - (BigInt.one << (8 * bytes.length));
  }

  /// The value of a small INTEGER or ENUMERATED.
  int get smallInteger {
    final number = integer;
    if (!number.isValidInt) throw const FormatException('INTEGER too large');
    return number.toInt();
  }

  /// The value of a BOOLEAN.
  bool get boolean => value.isNotEmpty && value[0] != 0;

  /// The value of an OBJECT IDENTIFIER, dotted: `2.23.136.1.1.1`.
  String get objectIdentifier => decodeObjectIdentifier(value);

  /// The bits of a BIT STRING that has no unused bits.
  Uint8List get bitString {
    final bytes = value;
    if (bytes.isEmpty || bytes[0] != 0) {
      throw const FormatException('Unsupported BIT STRING');
    }
    return Uint8List.sublistView(bytes, 1);
  }

  /// The value of a character string: UTF-8, printable, IA5, numeric,
  /// visible, T.61 (read as Latin-1) or BMP.
  String get text => switch (tag) {
        0x1E => String.fromCharCodes([
            for (var i = 0; i + 1 < value.length; i += 2)
              value[i] << 8 | value[i + 1],
          ]),
        0x14 => latin1.decode(value),
        _ => decodeText(value),
      };

  /// The value of a UTCTime or GeneralizedTime, in UTC.
  DateTime get time {
    final text = ascii.decode(value);
    final utc = tag == 0x17;
    final match = RegExp(
      utc
          ? r'^(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?Z$'
          : r'^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})?(?:\.\d+)?Z$',
    ).firstMatch(text);
    if (match == null) throw FormatException('Unsupported time', text);
    var year = int.parse(match[1]!);
    // UTCTime years 50 to 99 are 1950 to 1999, RFC 5280.
    if (utc) year += year < 50 ? 2000 : 1900;
    return DateTime.utc(
      year,
      int.parse(match[2]!),
      int.parse(match[3]!),
      int.parse(match[4]!),
      int.parse(match[5]!),
      int.parse(match[6] ?? '0'),
    );
  }

  @override
  String toString() =>
      'Tlv(${tag.toRadixString(16).toUpperCase()}, ${value.length} bytes)';
}

/// Runs [parse] over data from a chip or a file, turning the errors that
/// malformed input causes, such as a missing element or nesting too deep,
/// into a [FormatException].
T parseUntrusted<T>(T Function() parse) {
  try {
    return parse();
  } on FormatException {
    rethrow;
  } on Object catch (error) {
    throw FormatException('Malformed data (${error.runtimeType})');
  }
}

/// Decodes [bytes] as UTF-8, or as Latin-1 when they are not UTF-8.
String decodeText(List<int> bytes) {
  try {
    return utf8.decode(bytes);
  } on FormatException {
    return latin1.decode(bytes);
  }
}

/// The dotted form of the OBJECT IDENTIFIER whose value is [bytes].
String decodeObjectIdentifier(List<int> bytes) {
  if (bytes.isEmpty) throw const FormatException('Empty OBJECT IDENTIFIER');
  final parts = <int>[];
  var value = 0;
  for (final byte in bytes) {
    value = value << 7 | byte & 0x7F;
    if (byte & 0x80 == 0) {
      if (parts.isEmpty) {
        final first = value < 80 ? value ~/ 40 : 2;
        parts
          ..add(first)
          ..add(value - 40 * first);
      } else {
        parts.add(value);
      }
      value = 0;
    }
  }
  if (bytes.last & 0x80 != 0) {
    throw const FormatException('Truncated OBJECT IDENTIFIER');
  }
  return parts.join('.');
}

/// The value bytes of the OBJECT IDENTIFIER [dotted].
Uint8List encodeObjectIdentifier(String dotted) {
  final parts = dotted.split('.').map(int.parse).toList();
  final bytes = <int>[];
  void add(int number) {
    final groups = <int>[number & 0x7F];
    var rest = number >> 7;
    while (rest > 0) {
      groups.insert(0, rest & 0x7F | 0x80);
      rest >>= 7;
    }
    bytes.addAll(groups);
  }

  add(parts[0] * 40 + parts[1]);
  parts.skip(2).forEach(add);
  return Uint8List.fromList(bytes);
}

/// Encodes an element tagged [tag], definite length.
Uint8List tlv(int tag, List<int> value) {
  final tagBytes = <int>[];
  var rest = tag;
  do {
    tagBytes.insert(0, rest & 0xFF);
    rest >>= 8;
  } while (rest > 0);
  final length = value.length;
  final List<int> lengthBytes;
  if (length < 0x80) {
    lengthBytes = [length];
  } else if (length < 0x100) {
    lengthBytes = [0x81, length];
  } else if (length < 0x10000) {
    lengthBytes = [0x82, length >> 8, length & 0xFF];
  } else {
    lengthBytes = [0x83, length >> 16, length >> 8 & 0xFF, length & 0xFF];
  }
  return concat([tagBytes, lengthBytes, value]);
}

/// Encodes a SEQUENCE of already encoded [elements].
Uint8List derSequence(List<List<int>> elements) => tlv(0x30, concat(elements));

/// Encodes a SET of already encoded [elements], sorted as DER requires.
Uint8List derSet(List<List<int>> elements) {
  final sorted = [...elements]..sort(_compareBytes);
  return tlv(0x31, concat(sorted));
}

int _compareBytes(List<int> a, List<int> b) {
  for (var i = 0; i < a.length && i < b.length; i++) {
    if (a[i] != b[i]) return a[i] - b[i];
  }
  return a.length - b.length;
}

/// Encodes an INTEGER.
Uint8List derInteger(BigInt value) {
  if (value.isNegative) throw ArgumentError.value(value, 'value');
  final bytes = value == BigInt.zero
      ? Uint8List(1)
      : bigIntBytes(value, byteLength(value));
  // A leading bit set would make the number negative.
  return tlv(0x02, bytes[0] >= 0x80 ? [0, ...bytes] : bytes);
}

/// Encodes an OBJECT IDENTIFIER.
Uint8List derObjectIdentifier(String dotted) =>
    tlv(0x06, encodeObjectIdentifier(dotted));

/// Encodes an OCTET STRING.
Uint8List derOctetString(List<int> bytes) => tlv(0x04, bytes);

/// Encodes a BIT STRING with no unused bits.
Uint8List derBitString(List<int> bits) => tlv(0x03, [0, ...bits]);

/// Encodes a UTF8String.
Uint8List derUtf8String(String text) => tlv(0x0C, utf8.encode(text));

/// Encodes a PrintableString.
Uint8List derPrintableString(String text) => tlv(0x13, ascii.encode(text));

/// Encodes a time as a UTCTime before 2050, a GeneralizedTime after.
Uint8List derTime(DateTime time) {
  final utc = time.toUtc();
  String two(int value) => value.toString().padLeft(2, '0');
  final rest = '${two(utc.month)}${two(utc.day)}${two(utc.hour)}'
      '${two(utc.minute)}${two(utc.second)}Z';
  return utc.year < 2050
      ? tlv(0x17, ascii.encode('${two(utc.year % 100)}$rest'))
      : tlv(0x18, ascii.encode('${utc.year}$rest'));
}

/// Encodes NULL.
final derNull = Uint8List.fromList(const [0x05, 0x00]);
