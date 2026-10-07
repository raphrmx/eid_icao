import 'dart:typed_data';

/// Encodes 8 bit [pixels], [channels] per pixel (grey, grey and alpha, RGB,
/// RGBA), as a PNG file.
Uint8List encodePng(int width, int height, int channels, Uint8List pixels) {
  if (channels < 1 || channels > 4) throw ArgumentError.value(channels);
  if (pixels.length != width * height * channels) {
    throw ArgumentError('Expected ${width * height * channels} samples');
  }
  final out = BytesBuilder(copy: false)
    ..add(const [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]);
  final header = ByteData(13)
    ..setUint32(0, width)
    ..setUint32(4, height)
    ..setUint8(8, 8)
    ..setUint8(9, const [0, 4, 2, 6][channels - 1]);
  _chunk(out, 'IHDR', header.buffer.asUint8List());
  _chunk(out, 'IDAT', _zlib(_filter(width, height, channels, pixels)));
  _chunk(out, 'IEND', Uint8List(0));
  return out.takeBytes();
}

void _chunk(BytesBuilder out, String type, Uint8List data) {
  final typed = Uint8List(4 + data.length)
    ..setRange(0, 4, type.codeUnits)
    ..setRange(4, 4 + data.length, data);
  out
    ..add((ByteData(4)..setUint32(0, data.length)).buffer.asUint8List())
    ..add(typed)
    ..add((ByteData(4)..setUint32(0, _crc32(typed))).buffer.asUint8List());
}

final _crcTable = () {
  final table = Uint32List(256);
  for (var n = 0; n < 256; n++) {
    var c = n;
    for (var k = 0; k < 8; k++) {
      c = c & 1 != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
    }
    table[n] = c;
  }
  return table;
}();

int _crc32(Uint8List data) {
  var c = 0xFFFFFFFF;
  for (final byte in data) {
    c = _crcTable[(c ^ byte) & 0xFF] ^ (c >> 8);
  }
  return c ^ 0xFFFFFFFF;
}

// Each row behind the filter, among the five, whose output is smallest.
Uint8List _filter(int width, int height, int channels, Uint8List pixels) {
  final stride = width * channels;
  final out = Uint8List((stride + 1) * height);
  final zero = Uint8List(stride);
  for (var y = 0; y < height; y++) {
    final row = Uint8List.sublistView(pixels, y * stride, (y + 1) * stride);
    final above = y == 0
        ? zero
        : Uint8List.sublistView(pixels, (y - 1) * stride, y * stride);
    var bestType = 0;
    var bestCost = _cost(row, above, channels, 0, -1);
    for (var type = 1; type < 5; type++) {
      final cost = _cost(row, above, channels, type, bestCost);
      if (cost >= 0 && cost < bestCost) {
        bestCost = cost;
        bestType = type;
      }
    }
    final at = y * (stride + 1);
    out[at] = bestType;
    for (var i = 0; i < stride; i++) {
      final a = i >= channels ? row[i - channels] : 0;
      final c = i >= channels ? above[i - channels] : 0;
      out[at + 1 + i] = (row[i] - _predict(bestType, a, above[i], c)) & 0xFF;
    }
  }
  return out;
}

int _predict(int type, int a, int b, int c) => switch (type) {
      0 => 0,
      1 => a,
      2 => b,
      3 => (a + b) >> 1,
      _ => _paeth(a, b, c),
    };

// The sum of the filtered bytes as signed values, or -1 once over limit.
int _cost(Uint8List row, Uint8List above, int channels, int type, int limit) {
  var cost = 0;
  final n = row.length;
  int add(int value) {
    final v = value & 0xFF;
    return v < 128 ? v : 256 - v;
  }

  switch (type) {
    case 0:
      for (var i = 0; i < n; i++) {
        cost += add(row[i]);
      }
    case 1:
      for (var i = 0; i < n; i++) {
        cost += add(row[i] - (i >= channels ? row[i - channels] : 0));
        if (limit >= 0 && cost >= limit) return -1;
      }
    case 2:
      for (var i = 0; i < n; i++) {
        cost += add(row[i] - above[i]);
        if (limit >= 0 && cost >= limit) return -1;
      }
    case 3:
      for (var i = 0; i < n; i++) {
        final a = i >= channels ? row[i - channels] : 0;
        cost += add(row[i] - ((a + above[i]) >> 1));
        if (limit >= 0 && cost >= limit) return -1;
      }
    default:
      for (var i = 0; i < n; i++) {
        final a = i >= channels ? row[i - channels] : 0;
        final c = i >= channels ? above[i - channels] : 0;
        cost += add(row[i] - _paeth(a, above[i], c));
        if (limit >= 0 && cost >= limit) return -1;
      }
  }
  return cost;
}

int _paeth(int a, int b, int c) {
  final p = a + b - c;
  final pa = (p - a).abs();
  final pb = (p - b).abs();
  final pc = (p - c).abs();
  if (pa <= pb && pa <= pc) return a;
  return pb <= pc ? b : c;
}

Uint8List _zlib(Uint8List data) {
  final writer = _BitWriter()
    ..bits(0x78, 8)
    ..bits(0x9C, 8);
  _deflate(data, writer);
  writer.flush();
  var a = 1;
  var b = 0;
  for (var start = 0; start < data.length; start += 5552) {
    final end = start + 5552 < data.length ? start + 5552 : data.length;
    for (var i = start; i < end; i++) {
      a += data[i];
      b += a;
    }
    a %= 65521;
    b %= 65521;
  }
  final adler = b << 16 | a;
  for (final shift in const [24, 16, 8, 0]) {
    writer.bits((adler >> shift) & 0xFF, 8);
  }
  return writer.takeBytes();
}

final class _BitWriter {
  final _out = BytesBuilder();
  final _buffer = Uint8List(1 << 16);
  int _length = 0;
  int _bits = 0;
  int _count = 0;

  // Writes the count low bits of value, least significant first.
  void bits(int value, int count) {
    _bits |= value << _count;
    _count += count;
    while (_count >= 8) {
      _byte(_bits & 0xFF);
      _bits >>= 8;
      _count -= 8;
    }
  }

  void _byte(int value) {
    if (_length == _buffer.length) {
      _out.add(Uint8List.fromList(_buffer));
      _length = 0;
    }
    _buffer[_length++] = value;
  }

  void flush() {
    if (_count > 0) bits(0, 8 - _count);
  }

  Uint8List takeBytes() {
    _out.add(Uint8List.sublistView(_buffer, 0, _length));
    _length = 0;
    return _out.takeBytes();
  }
}

// The length and distance codes of RFC 1951 3.2.5: first value, extra bits.
final class _Codes {
  _Codes() {
    var base = 3;
    for (var code = 0; code < 28; code++) {
      final extra = code < 8 ? 0 : (code - 4) >> 2;
      lengthBase[code] = base;
      lengthExtra[code] = extra;
      for (var l = base; l < base + (1 << extra); l++) {
        lengthCode[l] = code;
      }
      base += 1 << extra;
    }
    lengthBase[28] = 258;
    lengthCode[258] = 28;
    var distance = 1;
    for (var code = 0; code < 30; code++) {
      final extra = code < 4 ? 0 : (code - 2) >> 1;
      distanceBase[code] = distance;
      distanceExtra[code] = extra;
      distance += 1 << extra;
    }
  }

  final lengthBase = Int32List(29);
  final lengthExtra = Int32List(29);
  final lengthCode = Uint8List(259);
  final distanceBase = Int32List(30);
  final distanceExtra = Int32List(30);

  // The code of distance d + 1 at d below 256, of d >> 7 above, as zlib.
  late final _distanceCodes = () {
    final table = Uint8List(512);
    for (var code = 0; code < 30; code++) {
      final first = distanceBase[code] - 1;
      final last = first + (1 << distanceExtra[code]);
      for (var d = first; d < last; d++) {
        if (d < 256) {
          table[d] = code;
        } else {
          table[256 + (d >> 7)] = code;
        }
      }
    }
    return table;
  }();

  int distanceCode(int distance) {
    final d = distance - 1;
    return d < 256 ? _distanceCodes[d] : _distanceCodes[256 + (d >> 7)];
  }
}

final _codes = _Codes();

const _window = 1 << 15;
const _hashBits = 15;
const _maxChain = 16;
const _blockTokens = 1 << 15;

void _deflate(Uint8List data, _BitWriter writer) {
  final head = Int32List(1 << _hashBits)..fillRange(0, 1 << _hashBits, -1);
  final previous = Int32List(_window);
  final lengths = Int32List(_blockTokens);
  final distances = Int32List(_blockTokens);
  var tokens = 0;
  var pos = 0;
  final end = data.length;

  int hash(int i) =>
      ((data[i] << 10) ^ (data[i + 1] << 5) ^ data[i + 2]) &
      ((1 << _hashBits) - 1);

  void insert(int i) {
    if (i + 2 >= end) return;
    final h = hash(i);
    previous[i & (_window - 1)] = head[h];
    head[h] = i;
  }

  void emit(int length, int distance) {
    lengths[tokens] = length;
    distances[tokens] = distance;
    tokens++;
    if (tokens == _blockTokens) {
      _block(writer, lengths, distances, tokens, false);
      tokens = 0;
    }
  }

  while (pos < end) {
    var bestLength = 0;
    var bestDistance = 0;
    if (pos + 2 < end) {
      var candidate = head[hash(pos)];
      var chain = _maxChain;
      final limit = end - pos < 258 ? end - pos : 258;
      while (candidate >= 0 && pos - candidate <= _window - 1 && chain-- > 0) {
        if (data[candidate + bestLength] == data[pos + bestLength]) {
          var length = 0;
          while (length < limit &&
              data[candidate + length] == data[pos + length]) {
            length++;
          }
          if (length > bestLength) {
            bestLength = length;
            bestDistance = pos - candidate;
            if (length == limit) break;
          }
        }
        final next = previous[candidate & (_window - 1)];
        if (next >= candidate) break;
        candidate = next;
      }
    }
    if (bestLength >= 3) {
      emit(bestLength, bestDistance);
      for (var i = 0; i < bestLength; i++) {
        insert(pos + i);
      }
      pos += bestLength;
    } else {
      emit(data[pos], 0);
      insert(pos);
      pos++;
    }
  }
  _block(writer, lengths, distances, tokens, true);
}

// A block with dynamic Huffman codes, RFC 1951 3.2.7.
void _block(_BitWriter writer, Int32List lengths, Int32List distances,
    int tokens, bool last) {
  final literalFrequencies = Int32List(286);
  final distanceFrequencies = Int32List(30);
  for (var i = 0; i < tokens; i++) {
    if (distances[i] == 0) {
      literalFrequencies[lengths[i]]++;
    } else {
      literalFrequencies[257 + _codes.lengthCode[lengths[i]]]++;
      distanceFrequencies[_codes.distanceCode(distances[i])]++;
    }
  }
  literalFrequencies[256] = 1;
  final literalLengths = _codeLengths(literalFrequencies, 15);
  final distanceLengths = _codeLengths(distanceFrequencies, 15);
  var used = 0;
  for (final l in distanceLengths) {
    if (l > 0) used++;
  }
  // At least two distance codes, which every decoder takes as complete.
  if (used == 0) {
    distanceLengths[0] = 1;
    distanceLengths[1] = 1;
  } else if (used == 1) {
    distanceLengths[distanceLengths[0] == 0 ? 0 : 1] = 1;
  }
  final literalCodes = _canonical(literalLengths);
  final distanceCodes = _canonical(distanceLengths);

  var literalCount = 286;
  while (literalCount > 257 && literalLengths[literalCount - 1] == 0) {
    literalCount--;
  }
  var distanceCount = 30;
  while (distanceCount > 1 && distanceLengths[distanceCount - 1] == 0) {
    distanceCount--;
  }
  final all = [
    ...literalLengths.sublist(0, literalCount),
    ...distanceLengths.sublist(0, distanceCount),
  ];

  // The code lengths, run-length coded with symbols 16, 17 and 18.
  final symbols = <int>[];
  final extras = <int>[];
  for (var i = 0; i < all.length;) {
    final value = all[i];
    var run = 1;
    while (i + run < all.length && all[i + run] == value) {
      run++;
    }
    i += run;
    if (value == 0) {
      while (run >= 11) {
        final n = run < 138 ? run : 138;
        symbols.add(18);
        extras.add(n - 11);
        run -= n;
      }
      if (run >= 3) {
        symbols.add(17);
        extras.add(run - 3);
        run = 0;
      }
    } else {
      symbols.add(value);
      extras.add(0);
      run--;
      while (run >= 3) {
        final n = run < 6 ? run : 6;
        symbols.add(16);
        extras.add(n - 3);
        run -= n;
      }
    }
    for (; run > 0; run--) {
      symbols.add(value);
      extras.add(0);
    }
  }
  final lengthFrequencies = Int32List(19);
  for (final s in symbols) {
    lengthFrequencies[s]++;
  }
  final lengthLengths = _codeLengths(lengthFrequencies, 7);
  final lengthCodes = _canonical(lengthLengths);
  const order = [
    16,
    17,
    18,
    0,
    8,
    7,
    9,
    6,
    10,
    5,
    11,
    4,
    12,
    3,
    13,
    2,
    14,
    1,
    15
  ];
  var orderCount = 19;
  while (orderCount > 4 && lengthLengths[order[orderCount - 1]] == 0) {
    orderCount--;
  }

  writer
    ..bits(last ? 1 : 0, 1)
    ..bits(2, 2)
    ..bits(literalCount - 257, 5)
    ..bits(distanceCount - 1, 5)
    ..bits(orderCount - 4, 4);
  for (var i = 0; i < orderCount; i++) {
    writer.bits(lengthLengths[order[i]], 3);
  }
  for (var i = 0; i < symbols.length; i++) {
    final s = symbols[i];
    writer.bits(lengthCodes[s], lengthLengths[s]);
    if (s == 16) writer.bits(extras[i], 2);
    if (s == 17) writer.bits(extras[i], 3);
    if (s == 18) writer.bits(extras[i], 7);
  }
  for (var i = 0; i < tokens; i++) {
    final distance = distances[i];
    if (distance == 0) {
      final literal = lengths[i];
      writer.bits(literalCodes[literal], literalLengths[literal]);
      continue;
    }
    final length = lengths[i];
    final code = _codes.lengthCode[length];
    writer.bits(literalCodes[257 + code], literalLengths[257 + code]);
    if (_codes.lengthExtra[code] > 0) {
      writer.bits(length - _codes.lengthBase[code], _codes.lengthExtra[code]);
    }
    final dc = _codes.distanceCode(distance);
    writer.bits(distanceCodes[dc], distanceLengths[dc]);
    if (_codes.distanceExtra[dc] > 0) {
      writer.bits(distance - _codes.distanceBase[dc], _codes.distanceExtra[dc]);
    }
  }
  writer.bits(literalCodes[256], literalLengths[256]);
}

// Huffman code lengths of at most limit bits for frequencies.
Int32List _codeLengths(Int32List frequencies, int limit) {
  final n = frequencies.length;
  final lengths = Int32List(n);
  final weights = Int32List.fromList(frequencies);
  while (true) {
    final symbols = [
      for (var i = 0; i < n; i++)
        if (weights[i] > 0) i,
    ];
    if (symbols.isEmpty) return lengths;
    if (symbols.length == 1) {
      lengths[symbols.first] = 1;
      return lengths;
    }
    symbols.sort(
        (a, b) => weights[a] != weights[b] ? weights[a] - weights[b] : a - b);
    // Two queues: the leaves in order, then the merged nodes as made.
    final count = symbols.length;
    final weight = Int32List(2 * count);
    final parent = Int32List(2 * count);
    for (var i = 0; i < count; i++) {
      weight[i] = weights[symbols[i]];
    }
    var leaf = 0;
    var node = count;
    var made = count;
    int smallest() {
      if (leaf < count && (node >= made || weight[leaf] <= weight[node])) {
        return leaf++;
      }
      return node++;
    }

    while (made < 2 * count - 1) {
      final a = smallest();
      final b = smallest();
      weight[made] = weight[a] + weight[b];
      parent[a] = made;
      parent[b] = made;
      made++;
    }
    final depth = Int32List(2 * count);
    for (var i = made - 2; i >= 0; i--) {
      depth[i] = depth[parent[i]] + 1;
    }
    var longest = 0;
    for (var i = 0; i < count; i++) {
      lengths[symbols[i]] = depth[i];
      if (depth[i] > longest) longest = depth[i];
    }
    if (longest <= limit) return lengths;
    for (var i = 0; i < n; i++) {
      if (weights[i] > 0) weights[i] = (weights[i] >> 1) | 1;
    }
  }
}

// The canonical codes of lengths, bit reversed for the writer.
Int32List _canonical(Int32List lengths) {
  final counts = Int32List(16);
  for (final l in lengths) {
    if (l > 0) counts[l]++;
  }
  final next = Int32List(16);
  var code = 0;
  for (var bits = 1; bits < 16; bits++) {
    code = (code + counts[bits - 1]) << 1;
    next[bits] = code;
  }
  final codes = Int32List(lengths.length);
  for (var i = 0; i < lengths.length; i++) {
    final l = lengths[i];
    if (l == 0) continue;
    var c = next[l]++;
    var reversed = 0;
    for (var k = 0; k < l; k++) {
      reversed = reversed << 1 | (c & 1);
      c >>= 1;
    }
    codes[i] = reversed;
  }
  return codes;
}
