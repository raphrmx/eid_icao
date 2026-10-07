import 'dart:typed_data';

import 'package:eid_icao/src/jpeg2000/codestream.dart';
import 'package:eid_icao/src/tlv.dart';

/// A decoded image: 8 bit samples, [channels] per pixel, row after row.
final class DecodedImage {
  /// [pixels] of an image [width] by [height].
  const DecodedImage(this.width, this.height, this.channels, this.pixels);

  /// Its width in pixels.
  final int width;

  /// Its height in pixels.
  final int height;

  /// Grey, grey and alpha, RGB or RGBA: 1 to 4.
  final int channels;

  /// The samples.
  final Uint8List pixels;
}

/// Decodes a JPEG 2000 image, a JP2 file or a bare codestream, to 8 bit
/// grey, RGB, with or without alpha.
///
/// Throws a [FormatException] if [bytes] are malformed, larger than
/// [maxPixels], or use what JPEG 2000 part 1 decoders need not support.
DecodedImage decodeJpeg2000(Uint8List bytes, {int maxPixels = 1 << 22}) =>
    parseUntrusted(() => _decode(bytes, maxPixels));

DecodedImage _decode(Uint8List bytes, int maxPixels) {
  if (bytes.length >= 2 && bytes[0] == 0xFF && bytes[1] == 0x4F) {
    return _render(decodeCodestream(bytes, maxPixels: maxPixels), null);
  }
  final file = _Jp2.parse(bytes);
  return _render(decodeCodestream(file.codestream, maxPixels: maxPixels), file);
}

// What a JP2 file says about its codestream, ISO/IEC 15444-1 annex I.
final class _Jp2 {
  _Jp2(this.codestream, this.colourSpace, this.palette, this.mapping,
      this.channels);

  factory _Jp2.parse(Uint8List bytes) {
    Uint8List? codestream;
    int? colourSpace;
    _Palette? palette;
    List<(int, int, int)>? mapping;
    List<(int, int, int)>? channels;

    void walk(int start, int end, bool top) {
      var pos = start;
      while (pos + 8 <= end) {
        var length = _u32(bytes, pos);
        final type = _u32(bytes, pos + 4);
        var header = 8;
        if (length == 1) {
          if (pos + 16 > end) throw const FormatException('Truncated box');
          length = _u32(bytes, pos + 8) * 0x100000000 + _u32(bytes, pos + 12);
          header = 16;
        } else if (length == 0) {
          length = end - pos;
        }
        if (length < header || pos + length > end) {
          if (type == _jp2c && top) {
            // A codestream box cut short: decode what there is.
            length = end - pos;
          } else {
            throw const FormatException('Truncated box');
          }
        }
        final from = pos + header;
        final to = pos + length;
        switch (type) {
          case _jp2h:
            if (top) walk(from, to, false);
          case _jp2c:
            codestream ??= Uint8List.sublistView(bytes, from, to);
          case _colr:
            if (to - from >= 7 && bytes[from] == 1) {
              colourSpace ??= _u32(bytes, from + 3);
            }
          case _pclr:
            palette = _Palette.parse(Uint8List.sublistView(bytes, from, to));
          case _cmap:
            mapping = [
              for (var i = from; i + 4 <= to; i += 4)
                (bytes[i] << 8 | bytes[i + 1], bytes[i + 2], bytes[i + 3]),
            ];
          case _cdef:
            if (to - from >= 2) {
              final count = bytes[from] << 8 | bytes[from + 1];
              channels = [
                for (var i = 0, at = from + 2;
                    i < count && at + 6 <= to;
                    i++, at += 6)
                  (
                    bytes[at] << 8 | bytes[at + 1],
                    bytes[at + 2] << 8 | bytes[at + 3],
                    bytes[at + 4] << 8 | bytes[at + 5],
                  ),
              ];
            }
        }
        pos = to;
      }
    }

    if (bytes.length < 12 || _u32(bytes, 4) != _signature) {
      throw const FormatException('Not a JP2 file');
    }
    walk(0, bytes.length, true);
    if (codestream == null) throw const FormatException('No codestream');
    return _Jp2(codestream!, colourSpace, palette, mapping, channels);
  }

  final Uint8List codestream;

  // The enumerated colour space of the first colr box: 16 sRGB, 17 grey,
  // 18 sYCC.
  final int? colourSpace;
  final _Palette? palette;

  // cmap: component, 0 direct or 1 through the palette, palette column.
  final List<(int, int, int)>? mapping;

  // cdef: channel, type (0 colour, 1 or 2 opacity), association.
  final List<(int, int, int)>? channels;
}

const _signature = 0x6A502020;
const _jp2h = 0x6A703268;
const _jp2c = 0x6A703263;
const _colr = 0x636F6C72;
const _pclr = 0x70636C72;
const _cmap = 0x636D6170;
const _cdef = 0x63646566;
const _sycc = 18;

int _u32(Uint8List b, int i) =>
    (b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3]) & 0xFFFFFFFF;

final class _Palette {
  _Palette(this.entries, this.depths, this.columns);

  factory _Palette.parse(Uint8List box) {
    if (box.length < 3) throw const FormatException('Bad palette');
    final entries = box[0] << 8 | box[1];
    final count = box[2];
    if (entries == 0 || entries > 1024 || count == 0) {
      throw const FormatException('Bad palette');
    }
    if (box.length < 3 + count) throw const FormatException('Bad palette');
    final depths = [for (var i = 0; i < count; i++) (box[3 + i] & 0x7F) + 1];
    final columns = [for (var i = 0; i < count; i++) Int32List(entries)];
    var at = 3 + count;
    for (var e = 0; e < entries; e++) {
      for (var i = 0; i < count; i++) {
        final size = (depths[i] + 7) >> 3;
        if (at + size > box.length) throw const FormatException('Bad palette');
        var value = 0;
        for (var k = 0; k < size; k++) {
          value = value << 8 | box[at + k];
        }
        columns[i][e] = value;
        at += size;
      }
    }
    return _Palette(entries, depths, columns);
  }

  final int entries;
  final List<int> depths;
  final List<Int32List> columns;
}

// A channel of the image: its samples at their resolution, ready to scale.
final class _Channel {
  _Channel(this.samples, this.width, this.height, this.dx, this.dy, this.x0,
      this.y0, this.depth, this.signed);

  factory _Channel.of(Component c) => _Channel(
      c.samples, c.width, c.height, c.dx, c.dy, c.x0, c.y0, c.depth, c.signed);

  final Int32List samples;
  final int width;
  final int height;
  final int dx;
  final int dy;
  final int x0;
  final int y0;
  final int depth;
  final bool signed;
}

DecodedImage _render(Codestream codestream, _Jp2? file) {
  final components = codestream.components;
  var channels = [for (final c in components) _Channel.of(c)];

  // The palette, which maps one component to several channels.
  final palette = file?.palette;
  final mapping = file?.mapping;
  if (palette != null && mapping != null) {
    channels = [
      for (final (index, type, column) in mapping)
        if (index >= components.length)
          throw const FormatException('Bad component mapping')
        else if (type == 1)
          _throughPalette(components[index], palette, column)
        else
          _Channel.of(components[index]),
    ];
  }

  // Colour channels in their order, opacity last.
  var colours = channels;
  _Channel? alpha;
  final definitions = file?.channels;
  if (definitions != null && definitions.isNotEmpty) {
    final ordered = <(int, _Channel)>[];
    for (final (index, type, association) in definitions) {
      if (index >= channels.length) continue;
      if (type == 1 || type == 2) {
        alpha ??= channels[index];
      } else if (type == 0) {
        ordered.add((association, channels[index]));
      }
    }
    ordered.sort((a, b) => a.$1 - b.$1);
    if (ordered.isNotEmpty) colours = [for (final (_, c) in ordered) c];
  } else if (channels.length == 2 || channels.length == 4) {
    alpha = channels.last;
    colours = channels.sublist(0, channels.length - 1);
  }
  if (colours.isEmpty) throw const FormatException('No colour channel');
  final rgb = colours.length >= 3;
  final out = [
    ...rgb ? colours.sublist(0, 3) : [colours.first],
    if (alpha != null) alpha,
  ];

  final area = codestream.area;
  final width = area.width;
  final height = area.height;
  final count = out.length;
  final pixels = Uint8List(width * height * count);
  final sycc = rgb && file?.colourSpace == _sycc;
  final values = Int32List(count);
  for (var y = 0; y < height; y++) {
    for (var x = 0; x < width; x++) {
      for (var k = 0; k < count; k++) {
        values[k] = _sample(out[k], area.x0 + x, area.y0 + y);
      }
      final at = (y * width + x) * count;
      if (sycc) {
        _syccToRgb(values, out);
      }
      for (var k = 0; k < count; k++) {
        pixels[at + k] = _to8Bits(values[k], out[k]);
      }
    }
  }
  return DecodedImage(width, height, count, pixels);
}

_Channel _throughPalette(Component c, _Palette palette, int column) {
  if (column >= palette.columns.length) {
    throw const FormatException('Bad palette column');
  }
  final entries = palette.columns[column];
  final samples = Int32List(c.samples.length);
  for (var i = 0; i < samples.length; i++) {
    var index = c.samples[i];
    if (index < 0) index = 0;
    if (index >= palette.entries) index = palette.entries - 1;
    samples[i] = entries[index];
  }
  return _Channel(samples, c.width, c.height, c.dx, c.dy, c.x0, c.y0,
      palette.depths[column], false);
}

// The sample of channel c nearest to (x, y) on the reference grid.
int _sample(_Channel c, int x, int y) {
  var u = x ~/ c.dx - c.x0;
  var v = y ~/ c.dy - c.y0;
  if (u < 0) u = 0;
  if (v < 0) v = 0;
  if (u >= c.width) u = c.width - 1;
  if (v >= c.height) v = c.height - 1;
  if (u < 0 || v < 0) return 0;
  return c.samples[v * c.width + u];
}

void _syccToRgb(Int32List values, List<_Channel> channels) {
  final depth = channels[0].depth;
  final offset = 1 << (depth - 1);
  final max = (1 << depth) - 1;
  final y = values[0];
  final cb = values[1] - offset;
  final cr = values[2] - offset;
  int clip(double v) {
    final rounded = (v + 0.5).floor();
    return rounded < 0 ? 0 : (rounded > max ? max : rounded);
  }

  values[0] = clip(y + 1.402 * cr);
  values[1] = clip(y - 0.344136 * cb - 0.714136 * cr);
  values[2] = clip(y + 1.772 * cb);
}

int _to8Bits(int value, _Channel c) {
  final depth = c.depth;
  var v = c.signed ? value + (1 << (depth - 1)) : value;
  final max = (1 << depth) - 1;
  if (v < 0) v = 0;
  if (v > max) v = max;
  if (depth == 8) return v;
  return (v * 255 + (max >> 1)) ~/ max;
}
