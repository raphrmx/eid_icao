import 'dart:typed_data';

// The probability estimation of the MQ decoder, ITU-T T.800 table C.2: for
// each state, Qe, the next state after an MPS, after an LPS, and whether an
// LPS swaps the MPS.
const _qe = [
  0x5601, 0x3401, 0x1801, 0x0AC1, 0x0521, 0x0221, 0x5601, 0x5401, 0x4801, //
  0x3801, 0x3001, 0x2401, 0x1C01, 0x1601, 0x5601, 0x5401, 0x5101, 0x4801,
  0x3801, 0x3401, 0x3001, 0x2801, 0x2401, 0x2201, 0x1C01, 0x1801, 0x1601,
  0x1401, 0x1201, 0x1101, 0x0AC1, 0x09C1, 0x08A1, 0x0521, 0x0441, 0x02A1,
  0x0221, 0x0141, 0x0111, 0x0085, 0x0049, 0x0025, 0x0015, 0x0009, 0x0005,
  0x0001, 0x5601,
];
const _nextMps = [
  1, 2, 3, 4, 5, 38, 7, 8, 9, 10, 11, 12, 13, 29, 15, 16, 17, 18, 19, 20, //
  21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
  40, 41, 42, 43, 44, 45, 45, 46,
];
const _nextLps = [
  1, 6, 9, 12, 29, 33, 6, 14, 14, 14, 17, 18, 20, 21, 14, 14, 15, 16, 17, //
  18, 19, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
  36, 37, 38, 39, 40, 41, 42, 43, 46,
];
const _switchMps = [
  1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, //
  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
];

// The contexts: zero coding 0 to 8, sign coding 9 to 13, magnitude
// refinement 14 to 16, run length and uniform.
const _contexts = 19;
const _runLength = 17;
const _uniform = 18;

// The arithmetic decoder of T.800 annex C, and the raw decoder of the bypass
// mode, over one codeword segment padded with two 0xFF bytes.
final class _MqDecoder {
  final Uint8List _state = Uint8List(_contexts);
  final Uint8List _mps = Uint8List(_contexts);
  Uint8List _data = Uint8List(2);
  int _bp = 0;
  int _a = 0;
  int _c = 0;
  int _ct = 0;

  void resetContexts() {
    _state.fillRange(0, _contexts, 0);
    _mps.fillRange(0, _contexts, 0);
    _state[0] = 4;
    _state[_runLength] = 3;
    _state[_uniform] = 46;
  }

  int _byte(int i) => i < _data.length ? _data[i] : 0xFF;

  void start(Uint8List data) {
    _data = data;
    _bp = 0;
    _c = _byte(0) << 16;
    _byteIn();
    _c = (_c << 7) & 0xFFFFFFFF;
    _ct -= 7;
    _a = 0x8000;
  }

  void _byteIn() {
    final next = _byte(_bp + 1);
    if (_byte(_bp) == 0xFF) {
      if (next > 0x8F) {
        _c += 0xFF00;
        _ct = 8;
      } else {
        _bp++;
        _c += next << 9;
        _ct = 7;
      }
    } else {
      _bp++;
      _c += next << 8;
      _ct = 8;
    }
  }

  int decode(int cx) {
    final s = _state[cx];
    final qe = _qe[s];
    var a = _a - qe;
    int d;
    if ((_c >> 16) < qe) {
      // The LPS subinterval, at the bottom, unless the exchange swaps them.
      if (a < qe) {
        d = _mps[cx];
        _state[cx] = _nextMps[s];
      } else {
        d = 1 - _mps[cx];
        if (_switchMps[s] == 1) _mps[cx] = d;
        _state[cx] = _nextLps[s];
      }
      a = qe;
    } else {
      _c -= qe << 16;
      if (a & 0x8000 != 0) {
        _a = a;
        return _mps[cx];
      }
      if (a < qe) {
        d = 1 - _mps[cx];
        if (_switchMps[s] == 1) _mps[cx] = d;
        _state[cx] = _nextLps[s];
      } else {
        d = _mps[cx];
        _state[cx] = _nextMps[s];
      }
    }
    do {
      if (_ct == 0) _byteIn();
      a <<= 1;
      _c = (_c << 1) & 0xFFFFFFFF;
      _ct--;
    } while (a & 0x8000 == 0);
    _a = a;
    return d;
  }

  void startRaw(Uint8List data) {
    _data = data;
    _bp = 0;
    _c = 0;
    _ct = 0;
  }

  int raw() {
    if (_ct == 0) {
      if (_c == 0xFF) {
        if (_byte(_bp) > 0x8F) {
          _ct = 8;
        } else {
          _c = _byte(_bp++);
          _ct = 7;
        }
      } else {
        _c = _byte(_bp++);
        _ct = 8;
      }
    }
    _ct--;
    return (_c >> _ct) & 1;
  }
}

// Flags of each sample: which of its eight neighbours are significant, the
// signs of the four nearest, and its own state.
const _nw = 0x1;
const _n = 0x2;
const _ne = 0x4;
const _w = 0x8;
const _e = 0x10;
const _sw = 0x20;
const _s = 0x40;
const _se = 0x80;
const _neighbours = 0xFF;
const _signN = 0x100;
const _signW = 0x200;
const _signE = 0x400;
const _signS = 0x800;
const _significant = 0x1000;
const _refined = 0x2000;
const _visited = 0x4000;
const _negative = 0x8000;

// In vertically causal mode, the stripe below reads as insignificant.
const _causal = ~(_sw | _s | _se | _signS);

/// The orientation of a subband.
enum Subband { ll, hl, lh, hh }

// Zero coding contexts, T.800 table D.1, indexed by the neighbour flags.
final _zeroLlLh = _zeroTable(Subband.ll);
final _zeroHl = _zeroTable(Subband.hl);
final _zeroHh = _zeroTable(Subband.hh);

Uint8List _zeroTable(Subband band) {
  final table = Uint8List(256);
  for (var f = 0; f < 256; f++) {
    var h = (f & _w != 0 ? 1 : 0) + (f & _e != 0 ? 1 : 0);
    var v = (f & _n != 0 ? 1 : 0) + (f & _s != 0 ? 1 : 0);
    final d = (f & _nw != 0 ? 1 : 0) +
        (f & _ne != 0 ? 1 : 0) +
        (f & _sw != 0 ? 1 : 0) +
        (f & _se != 0 ? 1 : 0);
    if (band == Subband.hl) (h, v) = (v, h);
    int context;
    if (band == Subband.hh) {
      final hv = h + v;
      context = switch (d) {
        >= 3 => 8,
        2 => hv >= 1 ? 7 : 6,
        1 => hv >= 2 ? 5 : (hv == 1 ? 4 : 3),
        _ => hv >= 2 ? 2 : hv,
      };
    } else if (h == 2) {
      context = 8;
    } else if (h == 1) {
      context = v >= 1 ? 7 : (d >= 1 ? 6 : 5);
    } else {
      context = v == 2 ? 4 : (v == 1 ? 3 : (d >= 2 ? 2 : d));
    }
    table[f] = context;
  }
  return table;
}

// Sign coding, T.800 table D.3: the context in the low bits, the bit to
// flip the decoded sign with in bit 4, indexed by the low 12 flags.
final _signTable = () {
  final table = Uint8List(4096);
  int contribution(int f, int significant, int negative) =>
      f & significant == 0 ? 0 : (f & negative != 0 ? -1 : 1);
  for (var f = 0; f < 4096; f++) {
    final h = (contribution(f, _w, _signW) + contribution(f, _e, _signE))
        .clamp(-1, 1);
    final v = (contribution(f, _n, _signN) + contribution(f, _s, _signS))
        .clamp(-1, 1);
    final flip = h < 0 || (h == 0 && v < 0);
    final hh = flip ? -h : h;
    final vv = flip ? -v : v;
    final context = hh == 1 ? 12 + vv : (vv == 0 ? 9 : 10);
    table[f] = context | (flip ? 0x10 : 0);
  }
  return table;
}();

/// The code-block coding styles of COD and COC.
abstract final class BlockStyle {
  /// Raw coding of the significance and refinement passes after the
  /// fourth bitplane.
  static const bypass = 0x01;

  /// The contexts reset after each pass.
  static const reset = 0x02;

  /// Each pass terminated, a codeword segment of its own.
  static const terminateAll = 0x04;

  /// Contexts that do not look at the stripe below.
  static const verticallyCausal = 0x08;

  /// A segmentation symbol after each cleanup pass.
  static const segmentationSymbols = 0x20;

  /// High throughput block coding, ITU-T T.814.
  static const highThroughput = 0x40;
}

/// A codeword segment of a code-block: its bytes and how many coding passes
/// they hold.
final class Segment {
  /// An empty segment of at most [maxPasses] passes.
  Segment(this.maxPasses);

  /// The most passes the segment can hold.
  final int maxPasses;

  /// The passes it holds so far.
  int passes = 0;

  final _chunks = <Uint8List>[];
  int _length = 0;

  /// Adds the bytes of the next packet.
  void add(Uint8List bytes) {
    if (bytes.isEmpty) return;
    _chunks.add(bytes);
    _length += bytes.length;
  }

  // The bytes, padded with two 0xFF for the decoders.
  Uint8List get padded {
    final out = Uint8List(_length + 2);
    var offset = 0;
    for (final chunk in _chunks) {
      out.setRange(offset, offset + chunk.length, chunk);
      offset += chunk.length;
    }
    out[_length] = 0xFF;
    out[_length + 1] = 0xFF;
    return out;
  }
}

/// Decodes a code-block of [width] by [height] samples from its [segments]:
/// [bitplanes] magnitude bitplanes, the first of which is coded by a
/// cleanup pass, then three passes per bitplane.
///
/// Returns the signed coefficients in half steps: each holds twice the
/// decoded magnitude, plus the middle of the range left undecoded.
Int32List decodeCodeBlock({
  required int width,
  required int height,
  required Subband band,
  required int style,
  required int bitplanes,
  required List<Segment> segments,
  int roiShift = 0,
}) {
  final coder = _BlockDecoder(width, height, band, style);
  coder.run(bitplanes, segments);
  final data = coder.data;
  final flags = coder.flags;
  final stride = width + 2;
  final threshold = roiShift > 0 ? 1 << (roiShift + 1) : 0;
  for (var y = 0; y < height; y++) {
    for (var x = 0; x < width; x++) {
      final i = y * width + x;
      var magnitude = data[i];
      if (magnitude == 0) continue;
      if (roiShift > 0 && magnitude >= threshold) magnitude >>= roiShift;
      if (flags[(y + 1) * stride + x + 1] & _negative != 0) {
        magnitude = -magnitude;
      }
      data[i] = magnitude;
    }
  }
  return data;
}

final class _BlockDecoder {
  _BlockDecoder(this.width, this.height, Subband band, this.style)
      : stride = width + 2,
        data = Int32List(width * height),
        flags = Int32List((width + 2) * (height + 2)),
        zero = switch (band) {
          Subband.hl => _zeroHl,
          Subband.hh => _zeroHh,
          _ => _zeroLlLh,
        },
        causal = style & BlockStyle.verticallyCausal != 0;

  final int width;
  final int height;
  final int style;
  final int stride;
  final Int32List data;
  final Int32List flags;
  final Uint8List zero;
  final bool causal;
  final _MqDecoder mq = _MqDecoder();
  bool _raw = false;

  void run(int bitplanes, List<Segment> segments) {
    if (bitplanes <= 0) return;
    mq.resetContexts();
    final bypass = style & BlockStyle.bypass != 0;
    var pass = 0;
    for (final segment in segments) {
      if (segment.passes == 0) continue;
      _raw = bypass && pass >= 10 && (pass - 1) % 3 != 2;
      final bytes = segment.padded;
      if (_raw) {
        mq.startRaw(bytes);
      } else {
        mq.start(bytes);
      }
      for (var k = 0; k < segment.passes; k++, pass++) {
        final plane = bitplanes - 1 - (pass + 2) ~/ 3;
        if (plane < 0) return;
        switch (pass == 0 ? 2 : (pass - 1) % 3) {
          case 0:
            _significancePass(plane);
          case 1:
            _refinementPass(plane);
          default:
            _cleanupPass(plane);
        }
        if (style & BlockStyle.reset != 0) mq.resetContexts();
      }
    }
  }

  // The flags of sample i at row y of the stripe from y0, as its contexts
  // see them.
  int _view(int i, int y, int y0) {
    final f = flags[i];
    return causal && y == y0 + 3 ? f & _causal : f;
  }

  int _bit(int context) => _raw ? mq.raw() : mq.decode(context);

  bool _decodeSign(int f) {
    if (_raw) return mq.raw() == 1;
    final entry = _signTable[f & 0xFFF];
    return (mq.decode(entry & 0xF) ^ (entry >> 4)) == 1;
  }

  void _becomeSignificant(int i, bool negative) {
    flags[i] |= _significant | (negative ? _negative : 0);
    flags[i - stride] |= _s | (negative ? _signS : 0);
    flags[i + stride] |= _n | (negative ? _signN : 0);
    flags[i - 1] |= _e | (negative ? _signE : 0);
    flags[i + 1] |= _w | (negative ? _signW : 0);
    flags[i - stride - 1] |= _se;
    flags[i - stride + 1] |= _sw;
    flags[i + stride - 1] |= _ne;
    flags[i + stride + 1] |= _nw;
  }

  void _significancePass(int plane) {
    final value = 3 << plane;
    for (var y0 = 0; y0 < height; y0 += 4) {
      final y1 = y0 + 4 < height ? y0 + 4 : height;
      for (var x = 0; x < width; x++) {
        for (var y = y0; y < y1; y++) {
          final i = (y + 1) * stride + x + 1;
          final f = _view(i, y, y0);
          if (f & _significant != 0 || f & _neighbours == 0) continue;
          if (_bit(zero[f & _neighbours]) == 1) {
            final negative = _decodeSign(f);
            data[y * width + x] = value;
            _becomeSignificant(i, negative);
          }
          flags[i] |= _visited;
        }
      }
    }
  }

  void _refinementPass(int plane) {
    final half = 1 << plane;
    for (var y0 = 0; y0 < height; y0 += 4) {
      final y1 = y0 + 4 < height ? y0 + 4 : height;
      for (var x = 0; x < width; x++) {
        for (var y = y0; y < y1; y++) {
          final i = (y + 1) * stride + x + 1;
          final f = _view(i, y, y0);
          if (f & (_significant | _visited) != _significant) continue;
          final context =
              f & _refined != 0 ? 16 : (f & _neighbours != 0 ? 15 : 14);
          final j = y * width + x;
          data[j] += _bit(context) == 1 ? half : -half;
          flags[i] |= _refined;
        }
      }
    }
  }

  void _cleanupPass(int plane) {
    final value = 3 << plane;
    for (var y0 = 0; y0 < height; y0 += 4) {
      final y1 = y0 + 4 < height ? y0 + 4 : height;
      for (var x = 0; x < width; x++) {
        var y = y0;
        if (y0 + 3 < height) {
          var quiet = true;
          for (var k = 0; k < 4 && quiet; k++) {
            final f = _view((y0 + k + 1) * stride + x + 1, y0 + k, y0);
            quiet = f & (_significant | _visited | _neighbours) == 0;
          }
          if (quiet) {
            if (mq.decode(_runLength) == 0) continue;
            y = y0 + (mq.decode(_uniform) << 1 | mq.decode(_uniform));
            final i = (y + 1) * stride + x + 1;
            final negative = _decodeSign(_view(i, y, y0));
            data[y * width + x] = value;
            _becomeSignificant(i, negative);
            y++;
          }
        }
        for (; y < y1; y++) {
          final i = (y + 1) * stride + x + 1;
          final f = _view(i, y, y0);
          if (f & (_significant | _visited) == 0 &&
              mq.decode(zero[f & _neighbours]) == 1) {
            final negative = _decodeSign(f);
            data[y * width + x] = value;
            _becomeSignificant(i, negative);
          }
          flags[i] &= ~_visited;
        }
      }
    }
    if (style & BlockStyle.segmentationSymbols != 0) {
      for (var k = 0; k < 4; k++) {
        mq.decode(_uniform);
      }
    }
  }
}
