import 'dart:math' as math;
import 'dart:typed_data';

import 'package:eid_icao/src/jpeg2000/tier1.dart';
import 'package:eid_icao/src/jpeg2000/wavelet.dart';

/// A component of a decoded codestream, at its own resolution.
final class Component {
  /// The samples of a component [width] by [height], one in [dx] by [dy]
  /// of the reference grid, [depth] bits, [signed] or not.
  Component({
    required this.width,
    required this.height,
    required this.dx,
    required this.dy,
    required this.x0,
    required this.y0,
    required this.depth,
    required this.signed,
  }) : samples = Int32List(width * height);

  /// Its width in samples.
  final int width;

  /// Its height in samples.
  final int height;

  /// Its horizontal subsampling of the reference grid.
  final int dx;

  /// Its vertical subsampling of the reference grid.
  final int dy;

  /// Its first column on its own grid: XOsiz over [dx].
  final int x0;

  /// Its first row on its own grid: YOsiz over [dy].
  final int y0;

  /// Its bits per sample.
  final int depth;

  /// Whether its samples are signed.
  final bool signed;

  /// Its samples, row after row.
  final Int32List samples;
}

/// The image of a codestream: its area on the reference grid and its
/// components.
final class Codestream {
  /// The image [area] and its [components].
  const Codestream(this.area, this.components);

  /// The image area on the reference grid.
  final Rect area;

  /// The components.
  final List<Component> components;
}

/// Decodes the JPEG 2000 codestream in [bytes], ITU-T T.800 part 1.
///
/// Throws a [FormatException] if it is malformed, larger than [maxPixels],
/// or uses what part 1 decoders need not support.
Codestream decodeCodestream(Uint8List bytes, {int maxPixels = 1 << 22}) =>
    _Decoder(bytes, maxPixels).decode();

// Marker codes.
const _soc = 0xFF4F;
const _siz = 0xFF51;
const _cod = 0xFF52;
const _coc = 0xFF53;
const _rgn = 0xFF5E;
const _qcd = 0xFF5C;
const _qcc = 0xFF5D;
const _poc = 0xFF5F;
const _ppm = 0xFF60;
const _ppt = 0xFF61;
const _sot = 0xFF90;
const _sod = 0xFF93;
const _eoc = 0xFFD9;

// The most code-blocks and precincts a codestream may hold.
const _maxBlocks = 1 << 19;

Never _unsupported(String what) =>
    throw FormatException('Unsupported JPEG 2000 $what');

Uint8List _concatenate(List<Uint8List> parts) {
  if (parts.length == 1) return parts.first;
  final builder = BytesBuilder(copy: false);
  parts.forEach(builder.add);
  return builder.takeBytes();
}

int _ceilDiv(int a, int b) => a >= 0 ? (a + b - 1) ~/ b : -((-a) ~/ b);

// A marker segment, read with bounds checks.
final class _Segment {
  _Segment(this._bytes, this._pos, this._end);

  final Uint8List _bytes;
  int _pos;
  final int _end;

  int get remaining => _end - _pos;

  int u8() {
    if (_pos >= _end) throw const FormatException('Truncated marker segment');
    return _bytes[_pos++];
  }

  int u16() => u8() << 8 | u8();

  int u32() => u16() << 16 | u16();

  Uint8List rest() {
    final out = Uint8List.sublistView(_bytes, _pos, _end);
    _pos = _end;
    return out;
  }
}

final class _ComponentSize {
  _ComponentSize(this.depth, this.signed, this.dx, this.dy);

  final int depth;
  final bool signed;
  final int dx;
  final int dy;
}

// The per-component coding style of COD or COC.
final class _Style {
  _Style(
    this.levels,
    this.blockWidth,
    this.blockHeight,
    this.blockStyle,
    this.reversible,
    this.precincts,
  );

  factory _Style.parse(_Segment s, bool withPrecincts) {
    final levels = s.u8();
    final blockWidth = s.u8() + 2;
    final blockHeight = s.u8() + 2;
    final blockStyle = s.u8();
    final transform = s.u8();
    if (levels > 32) throw const FormatException('Too many wavelet levels');
    if (blockWidth > 10 || blockHeight > 10 || blockWidth + blockHeight > 12) {
      throw const FormatException('Code-block too large');
    }
    if (blockStyle & BlockStyle.highThroughput != 0) {
      _unsupported('high throughput code-blocks');
    }
    if (transform > 1) _unsupported('wavelet transform');
    final precincts =
        withPrecincts ? [for (var r = 0; r <= levels; r++) s.u8()] : null;
    return _Style(
        levels, blockWidth, blockHeight, blockStyle, transform == 1, precincts);
  }

  final int levels;
  final int blockWidth;
  final int blockHeight;
  final int blockStyle;
  final bool reversible;
  final List<int>? precincts;

  int precinctWidth(int r) => precincts == null ? 15 : precincts![r] & 0xF;

  int precinctHeight(int r) => precincts == null ? 15 : precincts![r] >> 4;
}

final class _Cod {
  _Cod(this.scod, this.progression, this.layers, this.mct, this.style);

  final int scod;
  final int progression;
  final int layers;
  final int mct;
  final _Style style;

  bool get sop => scod & 2 != 0;

  bool get eph => scod & 4 != 0;
}

final class _Quantization {
  _Quantization(this.style, this.guardBits, this.exponents, this.mantissas);

  factory _Quantization.parse(_Segment s) {
    final sq = s.u8();
    final style = sq & 0x1F;
    final exponents = <int>[];
    final mantissas = <int>[];
    switch (style) {
      case 0:
        while (s.remaining > 0) {
          exponents.add(s.u8() >> 3);
          mantissas.add(0);
        }
      case 1 || 2:
        while (s.remaining > 1) {
          final value = s.u16();
          exponents.add(value >> 11);
          mantissas.add(value & 0x7FF);
        }
      default:
        throw const FormatException('Unknown quantization style');
    }
    if (exponents.isEmpty) throw const FormatException('Empty quantization');
    return _Quantization(style, sq >> 5, exponents, mantissas);
  }

  final int style;
  final int guardBits;
  final List<int> exponents;
  final List<int> mantissas;
}

final class _Progression {
  _Progression(this.r0, this.c0, this.layers, this.r1, this.c1, this.order);

  final int r0;
  final int c0;
  final int layers;
  final int r1;
  final int c1;
  final int order;
}

// The markers of the main header or of a tile's headers.
final class _Header {
  _Cod? cod;
  final coc = <int, _Style>{};
  _Quantization? qcd;
  final qcc = <int, _Quantization>{};
  final roi = <int, int>{};
  final progressions = <_Progression>[];
}

final class _TileData {
  final header = _Header();
  final parts = <Uint8List>[];
  final ppt = <Uint8List>[];
  final ppmChunks = <Uint8List>[];
}

final class _Decoder {
  _Decoder(this.bytes, this.maxPixels);

  final Uint8List bytes;
  final int maxPixels;
  final main = _Header();
  late final Rect area;
  late final int tileWidth;
  late final int tileHeight;
  late final int tileX0;
  late final int tileY0;
  late final List<_ComponentSize> sizes;
  late final int tilesWide;
  late final int tilesHigh;
  final _ppmMarkers = <Uint8List>[];
  int _blocks = 0;

  int _u16(int i) {
    if (i + 2 > bytes.length) throw const FormatException('Truncated');
    return bytes[i] << 8 | bytes[i + 1];
  }

  Codestream decode() {
    if (bytes.length < 4 || _u16(0) != _soc || _u16(2) != _siz) {
      throw const FormatException('Not a JPEG 2000 codestream');
    }
    var pos = 2;
    while (true) {
      final marker = _u16(pos);
      if (marker == _sot) break;
      if (marker >> 8 != 0xFF) throw const FormatException('Lost the markers');
      final length = _u16(pos + 2);
      if (length < 2 || pos + 2 + length > bytes.length) {
        throw const FormatException('Truncated header');
      }
      final segment = _Segment(bytes, pos + 4, pos + 2 + length);
      if (marker == _siz) {
        if (pos != 2) throw const FormatException('SIZ out of place');
        _parseSiz(segment);
      } else if (marker == _ppm) {
        segment.u8();
        _ppmMarkers.add(segment.rest());
      } else {
        _parseCoding(marker, segment, main);
      }
      pos += 2 + length;
    }
    if (main.cod == null || main.qcd == null) {
      throw const FormatException('No COD or QCD');
    }

    final tiles = List.generate(tilesWide * tilesHigh, (_) => _TileData());
    while (pos + 12 <= bytes.length && _u16(pos) == _sot) {
      final sot = _Segment(bytes, pos + 4, pos + 12);
      if (_u16(pos + 2) != 10) throw const FormatException('Bad SOT');
      final index = sot.u16();
      final length = sot.u32();
      sot.u8();
      sot.u8();
      if (index >= tiles.length) throw const FormatException('Bad tile index');
      final tile = tiles[index];
      final first = tile.parts.isEmpty;
      var end = length == 0 ? bytes.length : pos + length;
      if (end > bytes.length) end = bytes.length;
      if (length == 0 && end - 2 >= pos && _u16(end - 2) == _eoc) end -= 2;
      var at = pos + 12;
      while (true) {
        final marker = _u16(at);
        if (marker == _sod) break;
        final markerLength = _u16(at + 2);
        if (markerLength < 2 || at + 2 + markerLength > end) {
          throw const FormatException('Truncated tile header');
        }
        final segment = _Segment(bytes, at + 4, at + 2 + markerLength);
        if (marker == _ppt) {
          segment.u8();
          tile.ppt.add(segment.rest());
        } else if (first || marker == _poc) {
          _parseCoding(marker, segment, tile.header);
        }
        at += 2 + markerLength;
      }
      at += 2;
      tile.parts.add(Uint8List.sublistView(bytes, at, end < at ? at : end));
      if (_ppmMarkers.isNotEmpty) tile.ppmChunks.add(_nextPpmChunk());
      if (length == 0) break;
      pos = end;
    }

    final components = [
      for (final size in sizes)
        Component(
          width: _ceilDiv(area.x1, size.dx) - _ceilDiv(area.x0, size.dx),
          height: _ceilDiv(area.y1, size.dy) - _ceilDiv(area.y0, size.dy),
          dx: size.dx,
          dy: size.dy,
          x0: _ceilDiv(area.x0, size.dx),
          y0: _ceilDiv(area.y0, size.dy),
          depth: size.depth,
          signed: size.signed,
        ),
    ];
    for (var t = 0; t < tiles.length; t++) {
      if (tiles[t].parts.isEmpty) continue;
      _decodeTile(t, tiles[t], components);
    }
    return Codestream(area, components);
  }

  void _parseSiz(_Segment s) {
    s.u16();
    final x1 = s.u32();
    final y1 = s.u32();
    final x0 = s.u32();
    final y0 = s.u32();
    tileWidth = s.u32();
    tileHeight = s.u32();
    tileX0 = s.u32();
    tileY0 = s.u32();
    final count = s.u16();
    if (x1 <= x0 || y1 <= y0 || tileWidth == 0 || tileHeight == 0) {
      throw const FormatException('Empty image');
    }
    if (tileX0 > x0 ||
        tileY0 > y0 ||
        tileX0 + tileWidth <= x0 ||
        tileY0 + tileHeight <= y0) {
      throw const FormatException('Bad tile grid');
    }
    if ((x1 - x0) * (y1 - y0) > maxPixels) _unsupported('image size');
    if (count == 0 || count > 4) _unsupported('component count');
    area = Rect(x0, y0, x1, y1);
    sizes = [
      for (var c = 0; c < count; c++)
        () {
          final ssiz = s.u8();
          final dx = s.u8();
          final dy = s.u8();
          final depth = (ssiz & 0x7F) + 1;
          if (depth > 16) _unsupported('bit depth');
          if (dx == 0 || dy == 0) throw const FormatException('Bad sampling');
          return _ComponentSize(depth, ssiz & 0x80 != 0, dx, dy);
        }(),
    ];
    tilesWide = _ceilDiv(x1 - tileX0, tileWidth);
    tilesHigh = _ceilDiv(y1 - tileY0, tileHeight);
    if (tilesWide * tilesHigh > 65535) {
      throw const FormatException('Too many tiles');
    }
  }

  int _componentIndex(_Segment s) => sizes.length < 257 ? s.u8() : s.u16();

  void _parseCoding(int marker, _Segment s, _Header header) {
    switch (marker) {
      case _cod:
        final scod = s.u8();
        final progression = s.u8();
        final layers = s.u16();
        final mct = s.u8();
        if (progression > 4) throw const FormatException('Bad progression');
        if (layers == 0) throw const FormatException('No layers');
        header.cod = _Cod(
            scod, progression, layers, mct, _Style.parse(s, scod & 1 != 0));
      case _coc:
        final c = _componentIndex(s);
        final scoc = s.u8();
        if (c < sizes.length) header.coc[c] = _Style.parse(s, scoc & 1 != 0);
      case _qcd:
        header.qcd = _Quantization.parse(s);
      case _qcc:
        final c = _componentIndex(s);
        if (c < sizes.length) header.qcc[c] = _Quantization.parse(s);
      case _rgn:
        final c = _componentIndex(s);
        if (s.u8() != 0) _unsupported('region of interest style');
        final shift = s.u8();
        if (c < sizes.length) header.roi[c] = shift;
      case _poc:
        final wide = sizes.length >= 257;
        while (s.remaining >= (wide ? 9 : 7)) {
          final r0 = s.u8();
          final c0 = wide ? s.u16() : s.u8();
          final layers = s.u16();
          final r1 = s.u8();
          var c1 = wide ? s.u16() : s.u8();
          if (c1 == 0) c1 = 256;
          final order = s.u8();
          if (order > 4) throw const FormatException('Bad progression');
          header.progressions.add(_Progression(r0, c0, layers, r1, c1, order));
        }
    }
  }

  // The packet headers of the next tile-part, from the PPM markers.
  late final _ppmStream = _concatenate(_ppmMarkers);
  int _ppmPos = 0;

  Uint8List _nextPpmChunk() {
    final stream = _ppmStream;
    if (_ppmPos + 4 > stream.length) return Uint8List(0);
    final length = stream[_ppmPos] << 24 |
        stream[_ppmPos + 1] << 16 |
        stream[_ppmPos + 2] << 8 |
        stream[_ppmPos + 3];
    final start = _ppmPos + 4;
    final end = math.min(start + length, stream.length);
    _ppmPos = end;
    return Uint8List.sublistView(stream, start, end);
  }

  void _decodeTile(int index, _TileData data, List<Component> components) {
    final header = data.header;
    final cod = header.cod ?? main.cod!;
    final p = index % tilesWide;
    final q = index ~/ tilesWide;
    final tile = Rect(
      math.max(tileX0 + p * tileWidth, area.x0),
      math.max(tileY0 + q * tileHeight, area.y0),
      math.min(tileX0 + (p + 1) * tileWidth, area.x1),
      math.min(tileY0 + (q + 1) * tileHeight, area.y1),
    );
    final tileComponents = <_TileComponent>[];
    for (var c = 0; c < sizes.length; c++) {
      final style =
          header.coc[c] ?? header.cod?.style ?? main.coc[c] ?? main.cod!.style;
      final quantization =
          header.qcc[c] ?? header.qcd ?? main.qcc[c] ?? main.qcd!;
      final roi = header.roi[c] ?? main.roi[c] ?? 0;
      tileComponents
          .add(_buildComponent(tile, sizes[c], style, quantization, roi));
    }

    final stream = _concatenate(data.parts);
    final headers = data.ppmChunks.isNotEmpty
        ? _concatenate(data.ppmChunks)
        : data.ppt.isNotEmpty
            ? _concatenate(data.ppt)
            : null;
    final packets = _PacketReader(stream, headers, cod.sop, cod.eph);
    final progressions = header.progressions.isNotEmpty
        ? header.progressions
        : main.progressions.isNotEmpty
            ? main.progressions
            : [
                _Progression(
                    0, 0, cod.layers, 33, sizes.length, cod.progression)
              ];
    _readPackets(tile, tileComponents, progressions, cod.layers, packets);

    for (final component in tileComponents) {
      component.decodeBlocks();
      inverseWavelet(
        component.samples,
        component.rect.width,
        [for (final r in component.resolutions) r.rect],
        component.style.reversible,
      );
    }
    if (cod.mct == 1 && tileComponents.length >= 3) {
      _inverseColourTransform(tileComponents);
    }
    for (var c = 0; c < tileComponents.length; c++) {
      tileComponents[c].store(components[c]);
    }
  }

  _TileComponent _buildComponent(Rect tile, _ComponentSize size, _Style style,
      _Quantization quantization, int roi) {
    final rect = Rect(
      _ceilDiv(tile.x0, size.dx),
      _ceilDiv(tile.y0, size.dy),
      _ceilDiv(tile.x1, size.dx),
      _ceilDiv(tile.y1, size.dy),
    );
    final levels = style.levels;
    final component = _TileComponent(rect, size, style, roi);
    for (var r = 0; r <= levels; r++) {
      final scale = 1 << (levels - r);
      final resolution = _Resolution(
        Rect(
          _ceilDiv(rect.x0, scale),
          _ceilDiv(rect.y0, scale),
          _ceilDiv(rect.x1, scale),
          _ceilDiv(rect.y1, scale),
        ),
        levels - r,
        style.precinctWidth(r),
        style.precinctHeight(r),
      );
      final lower = r == 0 ? null : component.resolutions[r - 1].rect;
      final orientations = r == 0
          ? const [Subband.ll]
          : const [Subband.hl, Subband.lh, Subband.hh];
      for (var k = 0; k < orientations.length; k++) {
        final orientation = orientations[k];
        final nb = r == 0 ? levels : levels - r + 1;
        final xob =
            orientation == Subband.hl || orientation == Subband.hh ? 1 : 0;
        final yob =
            orientation == Subband.lh || orientation == Subband.hh ? 1 : 0;
        final bandRect = r == 0
            ? resolution.rect
            : Rect(
                _ceilDiv(rect.x0 - (xob << (nb - 1)), 1 << nb),
                _ceilDiv(rect.y0 - (yob << (nb - 1)), 1 << nb),
                _ceilDiv(rect.x1 - (xob << (nb - 1)), 1 << nb),
                _ceilDiv(rect.y1 - (yob << (nb - 1)), 1 << nb),
              );
        final bandIndex = r == 0 ? 0 : 1 + 3 * (r - 1) + k;
        int exponent;
        int mantissa;
        if (quantization.style == 1) {
          exponent = quantization.exponents[0] - levels + nb;
          mantissa = quantization.mantissas[0];
        } else {
          if (bandIndex >= quantization.exponents.length) {
            throw const FormatException('Too few quantization steps');
          }
          exponent = quantization.exponents[bandIndex];
          mantissa = quantization.mantissas[bandIndex];
        }
        if (exponent < 0) throw const FormatException('Bad quantization');
        final gain = xob + yob;
        final step = quantization.style == 0
            ? 1.0
            : math.pow(2, size.depth + gain - exponent) * (1 + mantissa / 2048);
        resolution.bands.add(_Band(
          orientation,
          bandRect,
          xob == 1 ? lower!.width : 0,
          yob == 1 ? lower!.height : 0,
          quantization.guardBits + exponent - 1,
          step,
          quantization.style == 0,
        ));
      }
      _buildPrecincts(tile, size, style, resolution, r);
      component.resolutions.add(resolution);
    }
    return component;
  }

  void _buildPrecincts(
    Rect tile,
    _ComponentSize size,
    _Style style,
    _Resolution resolution,
    int r,
  ) {
    final rect = resolution.rect;
    final ppx = resolution.ppx;
    final ppy = resolution.ppy;
    if (rect.width == 0 || rect.height == 0) return;
    if (r > 0 && (ppx == 0 || ppy == 0)) {
      throw const FormatException('Bad precinct size');
    }
    resolution.precinctsWide = _ceilDiv(rect.x1, 1 << ppx) - (rect.x0 >> ppx);
    resolution.precinctsHigh = _ceilDiv(rect.y1, 1 << ppy) - (rect.y0 >> ppy);
    final bandPpx = r == 0 ? ppx : ppx - 1;
    final bandPpy = r == 0 ? ppy : ppy - 1;
    final xcb = math.min(style.blockWidth, bandPpx);
    final ycb = math.min(style.blockHeight, bandPpy);
    final lev = resolution.level;
    for (var j = 0; j < resolution.precinctsHigh; j++) {
      for (var i = 0; i < resolution.precinctsWide; i++) {
        final px = ((rect.x0 >> ppx) + i) << ppx;
        final py = ((rect.y0 >> ppy) + j) << ppy;
        if (++_blocks > _maxBlocks) _unsupported('precinct count');
        final precinct = _Precinct(
          math.max(tile.x0, (px << lev) * size.dx),
          math.max(tile.y0, (py << lev) * size.dy),
        );
        for (final band in resolution.bands) {
          final bx0 = math.max(((rect.x0 >> ppx) + i) << bandPpx, band.rect.x0);
          final by0 = math.max(((rect.y0 >> ppy) + j) << bandPpy, band.rect.y0);
          final bx1 =
              math.min(((rect.x0 >> ppx) + i + 1) << bandPpx, band.rect.x1);
          final by1 =
              math.min(((rect.y0 >> ppy) + j + 1) << bandPpy, band.rect.y1);
          final blocks = <_Block>[];
          var wide = 0;
          var high = 0;
          if (bx1 > bx0 && by1 > by0) {
            final cx0 = bx0 >> xcb;
            final cy0 = by0 >> ycb;
            wide = _ceilDiv(bx1, 1 << xcb) - cx0;
            high = _ceilDiv(by1, 1 << ycb) - cy0;
            _blocks += wide * high;
            if (_blocks > _maxBlocks) _unsupported('code-block count');
            for (var y = 0; y < high; y++) {
              for (var x = 0; x < wide; x++) {
                blocks.add(_Block(Rect(
                  math.max((cx0 + x) << xcb, bx0),
                  math.max((cy0 + y) << ycb, by0),
                  math.min((cx0 + x + 1) << xcb, bx1),
                  math.min((cy0 + y + 1) << ycb, by1),
                )));
              }
            }
          }
          precinct.bands.add(_PrecinctBand(band, wide, high, blocks));
        }
        resolution.precincts.add(precinct);
      }
    }
  }

  void _readPackets(
    Rect tile,
    List<_TileComponent> components,
    List<_Progression> progressions,
    int layers,
    _PacketReader reader,
  ) {
    for (final progression in progressions) {
      final layerEnd = math.min(progression.layers, layers);
      final c0 = progression.c0;
      final c1 = math.min(progression.c1, components.length);
      final r0 = progression.r0;
      var r1 = 0;
      for (final component in components) {
        r1 = math.max(r1, component.resolutions.length);
      }
      r1 = math.min(progression.r1, r1);

      bool packet(_TileComponent component, _Resolution resolution,
          _Precinct precinct, int layer) {
        if (precinct.layers == layer) {
          reader.read(component, resolution, precinct, layer);
          precinct.layers++;
        }
        return !reader.exhausted;
      }

      switch (progression.order) {
        case 0 || 1:
          final layerFirst = progression.order == 0;
          final outer = layerFirst ? layerEnd : r1;
          final inner = layerFirst ? r1 : layerEnd;
          for (var a = layerFirst ? 0 : r0; a < outer; a++) {
            for (var b = layerFirst ? r0 : 0; b < inner; b++) {
              final layer = layerFirst ? a : b;
              final r = layerFirst ? b : a;
              for (var c = c0; c < c1; c++) {
                final component = components[c];
                if (r >= component.resolutions.length) continue;
                final resolution = component.resolutions[r];
                for (final precinct in resolution.precincts) {
                  if (!packet(component, resolution, precinct, layer)) return;
                }
              }
            }
          }
        default:
          final order = <(int, int, _Precinct)>[];
          for (var c = c0; c < c1; c++) {
            final resolutions = components[c].resolutions;
            for (var r = r0; r < r1 && r < resolutions.length; r++) {
              for (final precinct in resolutions[r].precincts) {
                order.add((c, r, precinct));
              }
            }
          }
          int compare((int, int, _Precinct) a, (int, int, _Precinct) b) {
            final (ca, ra, pa) = a;
            final (cb, rb, pb) = b;
            int position() => pa.y != pb.y ? pa.y - pb.y : pa.x - pb.x;
            return switch (progression.order) {
              2 =>
                ra != rb ? ra - rb : (position() != 0 ? position() : ca - cb),
              3 =>
                position() != 0 ? position() : (ca != cb ? ca - cb : ra - rb),
              _ =>
                ca != cb ? ca - cb : (position() != 0 ? position() : ra - rb),
            };
          }

          order.sort(compare);
          for (final (c, r, precinct) in order) {
            final component = components[c];
            for (var layer = 0; layer < layerEnd; layer++) {
              if (!packet(
                  component, component.resolutions[r], precinct, layer)) {
                return;
              }
            }
          }
      }
    }
  }

  void _inverseColourTransform(List<_TileComponent> components) {
    final a = components[0];
    final b = components[1];
    final c = components[2];
    final count = a.samples.length;
    if (b.samples.length != count ||
        c.samples.length != count ||
        a.rect.width != b.rect.width ||
        a.rect.width != c.rect.width) {
      throw const FormatException('Colour transform over unequal components');
    }
    final y = a.samples;
    final u = b.samples;
    final v = c.samples;
    if (a.style.reversible) {
      for (var i = 0; i < count; i++) {
        final g = y[i] - ((u[i] + v[i]) / 4).floorToDouble();
        final r = v[i] + g;
        final bl = u[i] + g;
        y[i] = r;
        u[i] = g;
        v[i] = bl;
      }
    } else {
      for (var i = 0; i < count; i++) {
        final yy = y[i];
        final cb = u[i];
        final cr = v[i];
        y[i] = yy + 1.402 * cr;
        u[i] = yy - 0.34413 * cb - 0.71414 * cr;
        v[i] = yy + 1.772 * cb;
      }
    }
  }
}

final class _TileComponent {
  _TileComponent(this.rect, this.size, this.style, this.roi)
      : samples = Float64List(rect.width * rect.height);

  final Rect rect;
  final _ComponentSize size;
  final _Style style;
  final int roi;
  final Float64List samples;
  final resolutions = <_Resolution>[];

  void decodeBlocks() {
    final stride = rect.width;
    for (final resolution in resolutions) {
      for (final precinct in resolution.precincts) {
        for (final band in precinct.bands) {
          final info = band.band;
          for (final block in band.blocks) {
            if (!block.included || block.segments.isEmpty) continue;
            final bitplanes = info.bitplanes + roi - block.zeroPlanes;
            if (bitplanes <= 0) continue;
            if (bitplanes > 30) _unsupported('coefficient precision');
            final width = block.rect.width;
            final height = block.rect.height;
            final values = decodeCodeBlock(
              width: width,
              height: height,
              band: info.orientation,
              style: style.blockStyle,
              bitplanes: bitplanes,
              segments: block.segments,
              roiShift: roi,
            );
            final x0 = info.offsetX + block.rect.x0 - info.rect.x0;
            final y0 = info.offsetY + block.rect.y0 - info.rect.y0;
            final step = info.step * 0.5;
            for (var y = 0; y < height; y++) {
              final row = (y0 + y) * stride + x0;
              final from = y * width;
              for (var x = 0; x < width; x++) {
                final value = values[from + x];
                if (value == 0) continue;
                samples[row + x] = info.integer
                    ? (value >= 0 ? value >> 1 : -((-value) >> 1)).toDouble()
                    : value * step;
              }
            }
          }
        }
      }
    }
  }

  // Shifts, rounds and clips the samples into the component.
  void store(Component component) {
    final depth = size.depth;
    final shift = size.signed ? 0 : 1 << (depth - 1);
    final low = size.signed ? -(1 << (depth - 1)) : 0;
    final high = size.signed ? (1 << (depth - 1)) - 1 : (1 << depth) - 1;
    final width = rect.width;
    final ox = rect.x0 - component.x0;
    final oy = rect.y0 - component.y0;
    for (var y = 0; y < rect.height; y++) {
      final to = (oy + y) * component.width + ox;
      final from = y * width;
      for (var x = 0; x < width; x++) {
        var value = (samples[from + x] + 0.5).floor() + shift;
        if (value < low) value = low;
        if (value > high) value = high;
        component.samples[to + x] = value;
      }
    }
  }
}

final class _Resolution {
  _Resolution(this.rect, this.level, this.ppx, this.ppy);

  final Rect rect;
  final int level;
  final int ppx;
  final int ppy;
  int precinctsWide = 0;
  int precinctsHigh = 0;
  final bands = <_Band>[];
  final precincts = <_Precinct>[];
}

final class _Band {
  _Band(
    this.orientation,
    this.rect,
    this.offsetX,
    this.offsetY,
    this.bitplanes,
    this.step,
    this.integer,
  );

  final Subband orientation;
  final Rect rect;
  final int offsetX;
  final int offsetY;
  final int bitplanes;
  final double step;
  final bool integer;
}

final class _Precinct {
  _Precinct(this.x, this.y);

  // Where the progression orders by position meet it on the reference grid.
  final int x;
  final int y;
  final bands = <_PrecinctBand>[];
  int layers = 0;
}

final class _PrecinctBand {
  _PrecinctBand(this.band, this.wide, this.high, this.blocks)
      : inclusion = blocks.isEmpty ? null : _TagTree(wide, high),
        zeroPlanes = blocks.isEmpty ? null : _TagTree(wide, high);

  final _Band band;
  final int wide;
  final int high;
  final List<_Block> blocks;
  final _TagTree? inclusion;
  final _TagTree? zeroPlanes;
}

final class _Block {
  _Block(this.rect);

  final Rect rect;
  bool included = false;
  int zeroPlanes = 0;
  int lengthBits = 3;
  final segments = <Segment>[];
}

// The bits of a packet header, with a 0 stuffed after each 0xFF.
final class _Bits {
  _Bits(this._data, this.pos);

  final Uint8List _data;
  int pos;
  int _byte = 0;
  int _left = 0;
  bool overrun = false;

  int bit() {
    if (_left == 0) {
      final stuffed = _byte == 0xFF;
      if (pos < _data.length) {
        _byte = _data[pos++];
      } else {
        overrun = true;
        _byte = 0;
      }
      _left = stuffed ? 7 : 8;
    }
    _left--;
    return (_byte >> _left) & 1;
  }

  int read(int count) {
    var value = 0;
    for (var i = 0; i < count; i++) {
      value = value << 1 | bit();
    }
    return value;
  }

  void align() {
    if (_byte == 0xFF) {
      if (pos < _data.length) {
        pos++;
      } else {
        overrun = true;
      }
    }
    _byte = 0;
    _left = 0;
  }
}

final class _TagTree {
  _TagTree(int wide, int high) {
    final widths = <int>[];
    final heights = <int>[];
    var w = wide;
    var h = high;
    while (true) {
      widths.add(w);
      heights.add(h);
      if (w * h <= 1) break;
      w = (w + 1) >> 1;
      h = (h + 1) >> 1;
    }
    final offsets = <int>[0];
    for (var k = 0; k < widths.length; k++) {
      offsets.add(offsets[k] + widths[k] * heights[k]);
    }
    final total = offsets.last;
    _value = Int32List(total)..fillRange(0, total, 1 << 30);
    _low = Int32List(total);
    _parent = Int32List(total)..fillRange(0, total, -1);
    _path = Int32List(widths.length);
    for (var k = 0; k + 1 < widths.length; k++) {
      for (var y = 0; y < heights[k]; y++) {
        for (var x = 0; x < widths[k]; x++) {
          _parent[offsets[k] + y * widths[k] + x] =
              offsets[k + 1] + (y >> 1) * widths[k + 1] + (x >> 1);
        }
      }
    }
  }

  late final Int32List _value;
  late final Int32List _low;
  late final Int32List _parent;
  late final Int32List _path;

  // Whether the value of leaf is below threshold, reading what it takes.
  bool decode(_Bits bits, int leaf, int threshold) {
    var depth = 0;
    for (var node = leaf; node != -1; node = _parent[node]) {
      _path[depth++] = node;
    }
    var low = 0;
    while (depth > 0) {
      final node = _path[--depth];
      if (low > _low[node]) {
        _low[node] = low;
      } else {
        low = _low[node];
      }
      while (low < threshold && low < _value[node]) {
        if (bits.bit() == 1) {
          _value[node] = low;
        } else {
          low++;
        }
      }
      _low[node] = low;
    }
    return _value[leaf] < threshold;
  }
}

int _floorLog2(int n) => n.bitLength - 1;

// The packets of a tile, their headers inline or from PPM or PPT markers.
final class _PacketReader {
  _PacketReader(this.data, this.headers, this.sop, this.eph);

  final Uint8List data;
  final Uint8List? headers;
  final bool sop;
  final bool eph;
  int pos = 0;
  int headerPos = 0;
  bool exhausted = false;

  void read(_TileComponent component, _Resolution resolution,
      _Precinct precinct, int layer) {
    if (sop &&
        pos + 6 <= data.length &&
        data[pos] == 0xFF &&
        data[pos + 1] == 0x91) {
      pos += 6;
    }
    final source = headers ?? data;
    final start = headers == null ? pos : headerPos;
    if (start >= source.length) {
      exhausted = true;
      return;
    }
    final bits = _Bits(source, start);
    final contributions = <(Segment, int)>[];
    if (bits.bit() == 1) {
      final blockStyle = component.style.blockStyle;
      for (final band in precinct.bands) {
        for (var b = 0; b < band.blocks.length; b++) {
          final block = band.blocks[b];
          final bool included;
          if (block.included) {
            included = bits.bit() == 1;
          } else {
            included = band.inclusion!.decode(bits, b, layer + 1);
          }
          if (bits.overrun) {
            exhausted = true;
            return;
          }
          if (!included) continue;
          if (!block.included) {
            var i = 0;
            while (!band.zeroPlanes!.decode(bits, b, i)) {
              if (++i > 64 || bits.overrun) {
                exhausted = true;
                return;
              }
            }
            block.zeroPlanes = i - 1;
            block.included = true;
          }
          var passes = _passCount(bits);
          while (bits.bit() == 1) {
            if (++block.lengthBits > 32 || bits.overrun) {
              exhausted = true;
              return;
            }
          }
          Segment? segment =
              block.segments.isEmpty ? null : block.segments.last;
          if (segment != null && segment.passes >= segment.maxPasses) {
            segment = null;
          }
          while (passes > 0) {
            segment ??= _newSegment(block, blockStyle);
            final take = math.min(segment.maxPasses - segment.passes, passes);
            final length = bits.read(block.lengthBits + _floorLog2(take));
            contributions.add((segment, length));
            segment.passes += take;
            passes -= take;
            if (segment.passes >= segment.maxPasses) segment = null;
          }
        }
      }
    }
    bits.align();
    if (bits.overrun) {
      exhausted = true;
      return;
    }
    var end = bits.pos;
    if (eph &&
        end + 2 <= source.length &&
        source[end] == 0xFF &&
        source[end + 1] == 0x92) {
      end += 2;
    }
    if (headers == null) {
      pos = end;
    } else {
      headerPos = end;
    }
    for (final (segment, length) in contributions) {
      var stop = pos + length;
      if (stop > data.length) {
        stop = data.length;
        exhausted = true;
      }
      segment.add(Uint8List.sublistView(data, pos, stop));
      pos = stop;
    }
  }

  static Segment _newSegment(_Block block, int style) {
    final int maxPasses;
    if (style & BlockStyle.terminateAll != 0) {
      maxPasses = 1;
    } else if (style & BlockStyle.bypass != 0) {
      if (block.segments.isEmpty) {
        maxPasses = 10;
      } else {
        final previous = block.segments.last.maxPasses;
        maxPasses = previous == 1 || previous == 10 ? 2 : 1;
      }
    } else {
      maxPasses = 1 << 30;
    }
    final segment = Segment(maxPasses);
    block.segments.add(segment);
    return segment;
  }

  static int _passCount(_Bits bits) {
    if (bits.bit() == 0) return 1;
    if (bits.bit() == 0) return 2;
    var n = bits.read(2);
    if (n < 3) return 3 + n;
    n = bits.read(5);
    if (n < 31) return 6 + n;
    return 37 + bits.read(7);
  }
}
