import 'dart:math' as math;

import 'package:eid_icao/src/mrz_scanner/blobs.dart';
import 'package:eid_icao/src/mrz_scanner/layout.dart';
import 'package:eid_icao/src/mrz_scanner/plane.dart';

/// The cells of the zone in [plane], or null when none is found.
MrzLayout? locate(GreyPlane plane) {
  // Blobs are found on a plane of at most 1400 pixels across: characters
  // stay a dozen pixels tall, the search stays quick.
  final longest = math.max(plane.width, plane.height);
  final factor = (longest / 1400).ceil();
  final small = plane.shrink(factor);
  final shortest = math.min(small.width, small.height);
  // A first window wide enough for any character; then, if the zone is
  // not whole, one fitted to the characters found, which a shadow or the
  // dark edge of the document upsets less.
  var window = math.max(15, shortest ~/ 5) | 1;
  for (var pass = 0; pass < 2; pass++) {
    final blobs = findBlobs(
      small,
      window: window,
      minHeight: 7,
      maxHeight: math.max(8, shortest ~/ 3),
    );
    final lines = findLines(blobs);
    final layout = findLayout(lines);
    if (layout != null) return layout.scaled(factor.toDouble());
    if (lines.isEmpty) return null;
    final heights = [for (final line in lines) line.charHeight]..sort();
    final fitted = math.max(15, (heights.last * 3).round()) | 1;
    if (fitted >= window) return null;
    window = fitted;
  }
  return null;
}
