import 'dart:typed_data';

import 'package:eid_icao/src/mrz.dart';
import 'package:eid_icao/src/mrz_scanner/ocrb_templates.dart';

/// What a position of the zone may hold, fillers always allowed: letters
/// (L), digits (D), letters and digits (A), a sex (S).
const Map<IcaoMrzFormat, List<String>> _kinds = {
  IcaoMrzFormat.td1: [
    'LLLLLAAAAAAAAADAAAAAAAAAAAAAAA',
    'DDDDDDDSDDDDDDDLLLAAAAAAAAAAAD',
    'LLLLLLLLLLLLLLLLLLLLLLLLLLLLLL',
  ],
  IcaoMrzFormat.td2: [
    'LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL',
    'AAAAAAAAADLLLDDDDDDDSDDDDDDDAAAAAAAD',
  ],
  IcaoMrzFormat.td3: [
    'LLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLLL',
    'AAAAAAAAADLLLDDDDDDDSDDDDDDDAAAAAAAAAAAAAADD',
  ],
};

/// The positions, lines run together, behind each check digit: the field
/// and its check digit, the optional data where a long document number
/// overflows.
const Map<IcaoMrzFormat, Map<IcaoMrzField, List<(int, int)>>> _spans = {
  IcaoMrzFormat.td1: {
    IcaoMrzField.documentNumber: [(5, 30)],
    IcaoMrzField.birthDate: [(30, 37)],
    IcaoMrzField.expiryDate: [(38, 45)],
    IcaoMrzField.composite: [(5, 30), (30, 37), (38, 45), (48, 60)],
  },
  IcaoMrzFormat.td2: {
    IcaoMrzField.documentNumber: [(36, 46), (64, 71)],
    IcaoMrzField.birthDate: [(49, 56)],
    IcaoMrzField.expiryDate: [(57, 64)],
    IcaoMrzField.composite: [(36, 46), (49, 56), (57, 72)],
  },
  IcaoMrzFormat.td3: {
    IcaoMrzField.documentNumber: [(44, 54)],
    IcaoMrzField.birthDate: [(57, 64)],
    IcaoMrzField.expiryDate: [(65, 72)],
    IcaoMrzField.personalNumber: [(72, 87)],
    IcaoMrzField.composite: [(44, 54), (57, 64), (65, 88)],
  },
};

const String _sexes = 'MFX<';

/// The farthest a replacement may score below the character read, in
/// natural logarithms, and how many replacements one reading may take.
const double _maxCost = 5;
const int _maxReplacements = 3;

/// A zone read from the scores of its cells, check digits put right where
/// a close second reading of a few characters satisfies them.
final class Decoded {
  Decoded._(this.text, this.mrz, this.replaced, this.cost, this.margin);

  /// The zone, one line per row.
  final String text;

  /// The zone parsed, or null when the text is no zone.
  final IcaoMrz? mrz;

  /// The positions taken from a second reading, to satisfy check digits.
  final List<int> replaced;

  /// How far below the first readings the replacements scored, summed.
  final double cost;

  /// The smallest lead of a character over the next allowed one.
  final double margin;

  /// Whether every check digit holds and the dates are dates.
  bool get isValid {
    final mrz = this.mrz;
    return mrz != null &&
        mrz.isValid &&
        mrz.birthDate != null &&
        mrz.expiryDate != null;
  }
}

/// The best zone of [format] from [scores], one list per cell, lines run
/// together, each scoring the characters of [ocrbAlphabet].
Decoded decode(IcaoMrzFormat format, List<Float32List> scores) {
  final kinds = _kinds[format]!.join();
  final width = format.lineLength;
  final chars = List<int>.filled(scores.length, 0);
  final options = <List<(int, double)>>[];
  var margin = double.infinity;
  for (var i = 0; i < scores.length; i++) {
    final allowed = _allowed(kinds[i]);
    final ranked = [for (final c in allowed) (c, scores[i][c])]
      ..sort((a, b) => b.$2.compareTo(a.$2));
    chars[i] = ranked.first.$1;
    if (ranked.length > 1) {
      final lead = ranked[0].$2 - ranked[1].$2;
      if (lead < margin) margin = lead;
    }
    options.add([
      for (final (c, s) in ranked.skip(1))
        if (ranked.first.$2 - s <= _maxCost) (c, ranked.first.$2 - s),
    ]);
  }

  String text(List<int> chars) {
    final buffer = StringBuffer();
    for (var i = 0; i < chars.length; i++) {
      if (i > 0 && i % width == 0) buffer.write('\n');
      buffer.write(ocrbAlphabet[chars[i]]);
    }
    return buffer.toString();
  }

  IcaoMrz? parse(String text) {
    try {
      return IcaoMrz.parse(text);
    } on FormatException {
      return null;
    }
  }

  final first = text(chars);
  final firstMrz = parse(first);
  final read = Decoded._(first, firstMrz, const [], 0, margin);
  if (firstMrz == null || read.isValid) return read;

  // Second readings where a check digit fails, cheapest first.
  final positions = <int>{
    for (final field in firstMrz.invalidFields)
      for (final (from, to) in _spans[format]![field] ?? const <(int, int)>[])
        for (var i = from; i < to; i++) i,
  };
  // A date that is no date fails no check digit but still needs a fix.
  if (firstMrz.birthDate == null) {
    positions.addAll(_spanOf(format, IcaoMrzField.birthDate));
  }
  if (firstMrz.expiryDate == null) {
    positions.addAll(_spanOf(format, IcaoMrzField.expiryDate));
  }
  final candidates = [
    for (final i in positions)
      for (final (c, cost) in options[i]) (i, c, cost),
  ]..sort((a, b) => a.$3.compareTo(b.$3));
  final pool = candidates.take(24).toList();

  final combos = <(double, List<(int, int, double)>)>[];
  void collect(int from, List<(int, int, double)> picked, double cost) {
    if (picked.isNotEmpty) combos.add((cost, [...picked]));
    if (picked.length == _maxReplacements) return;
    for (var k = from; k < pool.length; k++) {
      final candidate = pool[k];
      if (picked.any((p) => p.$1 == candidate.$1)) continue;
      // Three replacements only among the cheapest.
      if (picked.length == 2 && k >= 16) break;
      picked.add(candidate);
      collect(k + 1, picked, cost + candidate.$3);
      picked.removeLast();
    }
  }

  collect(0, [], 0);
  combos.sort((a, b) => a.$1.compareTo(b.$1));
  for (final (cost, picked) in combos) {
    final fixed = [...chars];
    for (final (i, c, _) in picked) {
      fixed[i] = c;
    }
    final candidate = text(fixed);
    final mrz = parse(candidate);
    final decoded = Decoded._(
      candidate,
      mrz,
      [for (final p in picked) p.$1]..sort(),
      cost,
      margin,
    );
    if (decoded.isValid) return decoded;
  }
  return read;
}

Iterable<int> _spanOf(IcaoMrzFormat format, IcaoMrzField field) sync* {
  for (final (from, to) in _spans[format]![field]!) {
    for (var i = from; i < to; i++) {
      yield i;
    }
  }
}

final List<int> _filler = [ocrbAlphabet.indexOf('<')];
final List<int> _digits = [for (var i = 0; i < 10; i++) i, ..._filler];
final List<int> _letters = [
  ..._filler,
  for (var i = 0; i < 26; i++)
    ocrbAlphabet.indexOf(String.fromCharCode(65 + i)),
];
final List<int> _any = [for (var i = 0; i < ocrbAlphabet.length; i++) i];
final List<int> _sex = [
  for (final c in _sexes.split('')) ocrbAlphabet.indexOf(c)
];

List<int> _allowed(String kind) => switch (kind) {
      'D' => _digits,
      'L' => _letters,
      'S' => _sex,
      _ => _any,
    };
