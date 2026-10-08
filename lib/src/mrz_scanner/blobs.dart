import 'dart:typed_data';

import 'package:eid_icao/src/mrz_scanner/plane.dart';

/// A patch of connected dark pixels: a character, most of the time.
final class Blob {
  /// A blob covering [left] to [right] and [top] to [bottom], ends
  /// included, of [area] pixels.
  Blob(this.left, this.top, this.right, this.bottom, this.area);

  /// The first column.
  final int left;

  /// The first row.
  final int top;

  /// The last column.
  final int right;

  /// The last row.
  final int bottom;

  /// The dark pixels.
  final int area;

  /// The width of the box.
  int get width => right - left + 1;

  /// The height of the box.
  int get height => bottom - top + 1;

  /// The centre of the box, across.
  double get centerX => (left + right + 1) / 2;

  /// The centre of the box, down.
  double get centerY => (top + bottom + 1) / 2;

  @override
  String toString() => 'Blob($left, $top, ${width}x$height)';
}

/// The dark patches of [plane] that may be characters: darker than their
/// surroundings by [contrast] percent over a window of [window] pixels,
/// joined at their edges and corners, between [minHeight] and [maxHeight]
/// pixels tall.
List<Blob> findBlobs(
  GreyPlane plane, {
  required int window,
  required int minHeight,
  required int maxHeight,
  int contrast = 12,
  int minDifference = 10,
}) {
  final width = plane.width;
  final height = plane.height;
  final half = window ~/ 2;
  final pixels = plane.pixels;

  // Runs of dark pixels, row by row: start, end (included), label.
  final parent = <int>[];
  final runStart = <int>[];
  final runEnd = <int>[];
  final runRow = <int>[];
  int find(int label) {
    var root = label;
    while (parent[root] != root) {
      root = parent[root];
    }
    var at = label;
    while (parent[at] != root) {
      final next = parent[at];
      parent[at] = root;
      at = next;
    }
    return root;
  }

  var previousFirst = 0;
  var previousCount = 0;
  for (var y = 0; y < height; y++) {
    final y0 = y - half < 0 ? 0 : y - half;
    final y1 = y + half + 1 > height ? height : y + half + 1;
    final row = y * width;
    final first = runStart.length;
    var start = -1;
    for (var x = 0; x <= width; x++) {
      var dark = false;
      if (x < width) {
        final x0 = x - half < 0 ? 0 : x - half;
        final x1 = x + half + 1 > width ? width : x + half + 1;
        final count = (x1 - x0) * (y1 - y0);
        final sum = plane.boxSum(x0, y0, x1, y1);
        final value = pixels[row + x];
        dark = value * count * 100 < sum * (100 - contrast) &&
            sum - value * count >= minDifference * count;
      }
      if (dark && start < 0) {
        start = x;
      } else if (!dark && start >= 0) {
        final label = parent.length;
        parent.add(label);
        runStart.add(start);
        runEnd.add(x - 1);
        runRow.add(y);
        // Joined to every run above that touches it, corners included.
        for (var i = previousFirst; i < previousFirst + previousCount; i++) {
          if (runStart[i] <= x && runEnd[i] >= start - 1) {
            final a = find(i);
            final b = find(label);
            if (a != b) parent[a > b ? a : b] = a > b ? b : a;
          }
        }
        start = -1;
      }
    }
    previousFirst = first;
    previousCount = runStart.length - first;
  }

  final runs = parent.length;
  final left = Int32List(runs)..fillRange(0, runs, 1 << 30);
  final top = Int32List(runs)..fillRange(0, runs, 1 << 30);
  final right = Int32List(runs)..fillRange(0, runs, -1);
  final bottom = Int32List(runs)..fillRange(0, runs, -1);
  final area = Int32List(runs);
  for (var i = 0; i < runs; i++) {
    final root = find(i);
    if (runStart[i] < left[root]) left[root] = runStart[i];
    if (runEnd[i] > right[root]) right[root] = runEnd[i];
    if (runRow[i] < top[root]) top[root] = runRow[i];
    if (runRow[i] > bottom[root]) bottom[root] = runRow[i];
    area[root] += runEnd[i] - runStart[i] + 1;
  }
  final blobs = <Blob>[];
  for (var i = 0; i < runs; i++) {
    if (parent[i] != i) continue;
    final h = bottom[i] - top[i] + 1;
    final w = right[i] - left[i] + 1;
    if (h < minHeight || h > maxHeight || w > h * 4) continue;
    // Thin strokes still fill a tenth of their box; noise lines do not.
    if (area[i] * 14 < w * h) continue;
    blobs.add(Blob(left[i], top[i], right[i], bottom[i], area[i]));
  }
  return blobs;
}
