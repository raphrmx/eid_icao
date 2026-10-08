import 'dart:math' as math;
import 'dart:typed_data';

import 'package:eid_icao/src/mrz_scanner/ocrb_templates.dart';

/// A white page with [lines] printed on it in OCR-B, from the templates the
/// recognizer matches against: [scale] pixels per template sample, turned
/// by [angle] radians about the centre, and [noise] grey levels of noise.
///
/// Returns the pixels, [width] by [height], one byte each.
Uint8List renderZone(
  List<String> lines, {
  required int width,
  required int height,
  double scale = 2,
  double angle = 0,
  int noise = 0,
  int seed = 1,
}) {
  final pitch = templateWidth * scale;
  final cell = templateHeight * scale;
  // A line every 1.9 character heights, as on a document.
  final charHeight = cell / (cellAbove + cellBelow);
  final spacing = charHeight * 1.9;
  final zoneWidth = lines.first.length * pitch;
  final zoneHeight = (lines.length - 1) * spacing + cell;
  final left = (width - zoneWidth) / 2;
  final top = (height - zoneHeight) / 2;
  final cos = math.cos(angle);
  final sin = math.sin(angle);
  final random = math.Random(seed);
  final out = Uint8List(width * height);
  for (var y = 0; y < height; y++) {
    for (var x = 0; x < width; x++) {
      // Back to the unturned page.
      final dx = x - width / 2;
      final dy = y - height / 2;
      final px = dx * cos + dy * sin + width / 2 - left;
      final py = -dx * sin + dy * cos + height / 2 - top;
      var ink = 0.0;
      final row = (py / spacing).floor();
      if (row >= 0 && row < lines.length && px >= 0 && px < zoneWidth) {
        final ty = (py - row * spacing) / scale;
        final column = (px / pitch).floor();
        final tx = (px - column * pitch) / scale;
        if (ty < templateHeight) {
          ink = _ink(lines[row][column], tx, ty);
        }
      }
      var value = 235 - 205 * ink;
      if (noise > 0) value += (random.nextDouble() * 2 - 1) * noise;
      out[y * width + x] = value.round().clamp(0, 255);
    }
  }
  return out;
}

// The ink of [char] at (x, y) in template samples, from 0 to 1, bilinear.
double _ink(String char, double x, double y) {
  final template = ocrbTemplates[ocrbAlphabet.indexOf(char)];
  final low = _low[char] ??= template.reduce(math.min);
  double at(int col, int row) {
    if (col < 0 || row < 0 || col >= templateWidth || row >= templateHeight) {
      return 0;
    }
    return (template[row * templateWidth + col] - low) / (127 - low);
  }

  final x0 = (x - 0.5).floor();
  final y0 = (y - 0.5).floor();
  final fx = x - 0.5 - x0;
  final fy = y - 0.5 - y0;
  return at(x0, y0) * (1 - fx) * (1 - fy) +
      at(x0 + 1, y0) * fx * (1 - fy) +
      at(x0, y0 + 1) * (1 - fx) * fy +
      at(x0 + 1, y0 + 1) * fx * fy;
}

final Map<String, int> _low = {};
