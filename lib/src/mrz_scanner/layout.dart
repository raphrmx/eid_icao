import 'dart:math' as math;

import 'package:eid_icao/src/mrz.dart';
import 'package:eid_icao/src/mrz_scanner/blobs.dart';

/// Where one character of the zone sits: the middle of its cell on the
/// baseline, the pitch and the character height, the slant of the line.
final class CellGeometry {
  /// A cell on the baseline at ([x], [y]).
  const CellGeometry(this.x, this.y, this.pitch, this.height, this.angle);

  /// The middle of the cell, across.
  final double x;

  /// The baseline under the middle of the cell.
  final double y;

  /// The distance to the next cell.
  final double pitch;

  /// The height of a letter.
  final double height;

  /// The slant of the line, in radians, clockwise.
  final double angle;

  /// The same cell in an image [factor] times larger.
  CellGeometry scaled(double factor) => CellGeometry(
        x * factor,
        y * factor,
        pitch * factor,
        height * factor,
        angle,
      );
}

/// The cells of a zone found in an image: one row per line.
final class MrzLayout {
  /// The [cells] of a zone in the [format].
  const MrzLayout(this.format, this.cells);

  /// The layout.
  final IcaoMrzFormat format;

  /// The cells, line by line, left to right.
  final List<List<CellGeometry>> cells;

  /// The same layout in an image [factor] times larger.
  MrzLayout scaled(double factor) => factor == 1
      ? this
      : MrzLayout(format, [
          for (final line in cells) [for (final c in line) c.scaled(factor)],
        ]);
}

/// A row of characters: blobs side by side on a common baseline.
final class TextLine {
  TextLine._(
    this.blobs,
    this.slope,
    this.intercept,
    this.charHeight,
    this.pitch,
  );

  /// The blobs, left to right.
  final List<Blob> blobs;

  /// The baseline: y = [intercept] + [slope] x.
  final double slope;

  /// See [slope].
  final double intercept;

  /// The height of the tall characters, letters and digits.
  final double charHeight;

  /// The distance between neighbouring characters.
  final double pitch;

  /// The baseline under [x].
  double baselineAt(double x) => intercept + slope * x;

  /// The middle of the first blob.
  double get startX => blobs.first.centerX;

  /// The middle of the last blob.
  double get endX => blobs.last.centerX;

  /// How many characters the line seems to hold.
  double get count => (endX - startX) / pitch + 1;

  /// The baseline in the middle of the line.
  double get middleY => baselineAt((startX + endX) / 2);

  @override
  String toString() => 'TextLine(${count.toStringAsFixed(1)} chars, '
      'h ${charHeight.toStringAsFixed(1)}, '
      'pitch ${pitch.toStringAsFixed(1)}, y ${middleY.toStringAsFixed(1)})';
}

/// The machine readable zone among [lines], or null when none is there.
MrzLayout? findLayout(List<TextLine> lines) => _bestBlock(lines);

/// The rows of characters among [blobs], as long as a line of a zone could
/// be.
List<TextLine> findLines(List<Blob> blobs) {
  final chains = _mergeChains(_chains(blobs));
  final lines = <TextLine>[];
  for (final chain in chains) {
    if (chain.length < 8) continue;
    final line = _fit(chain);
    if (line != null && line.count >= 24) lines.add(line);
  }
  lines.sort((a, b) => a.middleY.compareTo(b.middleY));
  return lines;
}

// Each blob linked to its nearest neighbour on the right that looks like
// the next character of the same row.
List<List<Blob>> _chains(List<Blob> blobs) {
  final sorted = [...blobs]..sort((a, b) => a.left.compareTo(b.left));
  final n = sorted.length;
  final next = List<int>.filled(n, -1);
  final nextScore = List<double>.filled(n, double.infinity);
  final previous = List<int>.filled(n, -1);
  final previousScore = List<double>.filled(n, double.infinity);
  for (var i = 0; i < n; i++) {
    final a = sorted[i];
    for (var j = i + 1; j < n; j++) {
      final b = sorted[j];
      final tall = math.max(a.height, b.height);
      if (b.left > a.right + tall * 1.1) break;
      if (b.centerX < a.centerX + tall * 0.3) continue;
      if (math.min(a.height, b.height) < tall * 0.5) continue;
      final dy = (b.centerY - a.centerY).abs();
      if (dy > tall * 0.3) continue;
      final score = (b.centerX - a.centerX) + dy * 3;
      if (score < nextScore[i]) {
        nextScore[i] = score;
        next[i] = j;
      }
    }
    final j = next[i];
    if (j >= 0 && nextScore[i] < previousScore[j]) {
      previousScore[j] = nextScore[i];
      previous[j] = i;
    }
  }
  final chains = <List<Blob>>[];
  for (var i = 0; i < n; i++) {
    final p = previous[i];
    // A chain starts where no blob links to it.
    if (p >= 0 && next[p] == i) continue;
    final chain = <Blob>[];
    var at = i;
    while (true) {
      chain.add(sorted[at]);
      final j = next[at];
      if (j < 0 || previous[j] != at) break;
      at = j;
    }
    chains.add(chain);
  }
  return chains;
}

// Chains that one gap broke in two, as a character lost to a reflection,
// joined again.
List<List<Blob>> _mergeChains(List<List<Blob>> chains) {
  final long = chains.where((chain) => chain.length >= 4).toList()
    ..sort((a, b) => a.first.left.compareTo(b.first.left));
  final used = List<bool>.filled(long.length, false);
  final merged = <List<Blob>>[];
  for (var i = 0; i < long.length; i++) {
    if (used[i]) continue;
    final chain = [...long[i]];
    used[i] = true;
    var joined = true;
    while (joined) {
      joined = false;
      final last = chain.last;
      final tall = _typicalHeight(chain);
      // The row carried on over the gap, at its own slant.
      final (slope, intercept) = _leastSquares(
        [for (final b in chain) b.centerX],
        [for (final b in chain) b.centerY],
      );
      for (var j = 0; j < long.length; j++) {
        if (used[j]) continue;
        final first = long[j].first;
        final gap = first.left - last.right;
        if (gap < 0 || gap > tall * 5) continue;
        final expected = intercept + slope * first.centerX;
        if ((first.centerY - expected).abs() > tall * 0.35) continue;
        final other = _typicalHeight(long[j]);
        if (other < tall * 0.8 || other > tall * 1.25) continue;
        chain.addAll(long[j]);
        used[j] = true;
        joined = true;
        break;
      }
    }
    merged.add(chain);
  }
  return merged;
}

// The height of the tall blobs of a row, letters and digits: fillers,
// shorter, may fill most of a line.
double _typicalHeight(List<Blob> chain) {
  final heights = chain.map((b) => b.height).toList()..sort();
  return heights[(heights.length * 9) ~/ 10].toDouble();
}

double _median(List<double> values) {
  final sorted = [...values]..sort();
  return sorted[sorted.length ~/ 2];
}

TextLine? _fit(List<Blob> chain) {
  final typical = _typicalHeight(chain);
  final tall = chain
      .where(
        (b) =>
            b.height >= typical * 0.85 &&
            b.height <= typical * 1.25 &&
            b.width <= typical * 1.3,
      )
      .toList();
  if (tall.length < 5) return null;
  var (slope, intercept) = _leastSquares(
    [for (final b in tall) b.centerX],
    [for (final b in tall) b.bottom + 1.0],
  );
  // Once more without the blobs off the line: a comma, a stray mark.
  final kept = tall
      .where(
        (b) =>
            (b.bottom + 1 - (intercept + slope * b.centerX)).abs() <=
            typical * 0.15,
      )
      .toList();
  if (kept.length >= 5 && kept.length < tall.length) {
    (slope, intercept) = _leastSquares(
      [for (final b in kept) b.centerX],
      [for (final b in kept) b.bottom + 1.0],
    );
  }
  final height = _median([for (final b in kept) b.height.toDouble()]);
  final steps = <double>[];
  for (var i = 1; i < chain.length; i++) {
    final a = chain[i - 1];
    final b = chain[i];
    if (a.width <= height * 1.1 && b.width <= height * 1.1) {
      steps.add(b.centerX - a.centerX);
    }
  }
  if (steps.length < 4) return null;
  final median = _median(steps);
  final close =
      steps.where((s) => s > median * 0.75 && s < median * 1.25).toList();
  final pitch = close.reduce((a, b) => a + b) / close.length;
  return TextLine._(chain, slope, intercept, height, pitch);
}

(double, double) _leastSquares(List<double> xs, List<double> ys) {
  final n = xs.length;
  var sx = 0.0;
  var sy = 0.0;
  for (var i = 0; i < n; i++) {
    sx += xs[i];
    sy += ys[i];
  }
  final mx = sx / n;
  final my = sy / n;
  var sxx = 0.0;
  var sxy = 0.0;
  for (var i = 0; i < n; i++) {
    sxx += (xs[i] - mx) * (xs[i] - mx);
    sxy += (xs[i] - mx) * (ys[i] - my);
  }
  final slope = sxx == 0 ? 0.0 : sxy / sxx;
  return (slope, my - slope * mx);
}

// The lines that make a zone: two or three alike, one under the other.
MrzLayout? _bestBlock(List<TextLine> lines) {
  ({double cost, List<TextLine> lines, IcaoMrzFormat format})? best;
  for (var i = 0; i < lines.length; i++) {
    for (final size in const [3, 2]) {
      if (i + size > lines.length) continue;
      final group = lines.sublist(i, i + size);
      if (!_alike(group)) continue;
      final counts = group.map((line) => line.count);
      final mean = counts.reduce((a, b) => a + b) / size;
      final IcaoMrzFormat format;
      if (size == 3) {
        format = IcaoMrzFormat.td1;
      } else {
        format = mean > 40 ? IcaoMrzFormat.td3 : IcaoMrzFormat.td2;
      }
      final n = format.lineLength;
      // The longest line holds every character: a short one lost an end.
      final longest = counts.reduce(math.max);
      final miss = (longest - n).abs();
      if (miss > 2.5) continue;
      // Three lines are a stronger find than two; lower is better.
      final cost = miss + (size == 3 ? 0 : 1.5);
      if (best == null || cost < best.cost) {
        best = (cost: cost, lines: group, format: format);
      }
    }
  }
  if (best == null) return null;
  return _lattice(best.lines, best.format);
}

bool _alike(List<TextLine> group) {
  final first = group.first;
  for (var i = 1; i < group.length; i++) {
    final above = group[i - 1];
    final line = group[i];
    final pitch = line.pitch / first.pitch;
    final height = line.charHeight / first.charHeight;
    if (pitch < 0.85 || pitch > 1.18) return false;
    if (height < 0.7 || height > 1.4) return false;
    if ((line.slope - first.slope).abs() > 0.05) return false;
    final spacing = line.middleY - above.middleY;
    final h = (line.charHeight + above.charHeight) / 2;
    if (spacing < h * 1.2 || spacing > h * 2.9) return false;
    final mid = (line.startX + line.endX) / 2 - (above.startX + above.endX) / 2;
    if (mid.abs() > first.pitch * 12) return false;
  }
  return true;
}

// The cells of each line: the characters are evenly spaced, the lines of
// equal length and left aligned.
MrzLayout _lattice(List<TextLine> lines, IcaoMrzFormat format) {
  final n = format.lineLength;
  // The lines whose ends are both found set the start and the pitch.
  final whole = lines.where((line) => (line.count - n).abs() < 0.6).toList();
  final reference = whole.isNotEmpty ? whole : lines;
  final slope = _median([for (final line in lines) line.slope]);
  // The left edge of the zone runs square to its lines: on a slanted zone,
  // each line starts a little aside of the one above.
  var start = 0.0;
  var pitch = 0.0;
  for (final line in reference) {
    final p =
        whole.isNotEmpty ? (line.endX - line.startX) / (n - 1) : line.pitch;
    start += line.startX + slope * line.middleY;
    pitch += p;
  }
  start /= reference.length;
  pitch /= reference.length;
  final cells = <List<CellGeometry>>[];
  for (final line in lines) {
    final own = whole.contains(line);
    final lineStart = own ? line.startX : start - slope * line.middleY;
    final linePitch = own ? (line.endX - line.startX) / (n - 1) : pitch;
    final position = _refine(line, lineStart, linePitch, n);
    final angle = math.atan(line.slope);
    cells.add([
      for (var i = 0; i < n; i++)
        CellGeometry(
          position(i),
          line.baselineAt(position(i)),
          (position(i + 0.5) - position(i - 0.5)) *
              math.sqrt(1 + slope * slope),
          line.charHeight,
          angle,
        ),
    ]);
  }
  return MrzLayout(format, cells);
}

// The middle of each cell from the blobs that fall into one: a slight
// curve follows the perspective of a tilted document.
double Function(num) _refine(
  TextLine line,
  double start,
  double pitch,
  int n,
) {
  final slots = <double>[];
  final xs = <double>[];
  for (final blob in line.blobs) {
    if (blob.width > line.charHeight * 1.2) continue;
    final at = (blob.centerX - start) / pitch;
    final slot = at.roundToDouble();
    if (slot < 0 || slot >= n || (at - slot).abs() > 0.3) continue;
    slots.add(slot);
    xs.add(blob.centerX);
  }
  double linear(num i) => start + pitch * i;
  if (slots.length < 8) return linear;
  final low = slots.reduce(math.min);
  final high = slots.reduce(math.max);
  if (high - low < n / 2) return linear;
  final fit = _quadratic(slots, xs);
  if (fit == null) return linear;
  final (a, b, c) = fit;
  // A tilted document spaces its characters wider on the near side; a
  // spacing that changes by more than a fifth over the line is no tilt.
  if ((c * n).abs() > pitch * 0.2) return linear;
  return (i) => a + b * i + c * i * i;
}

(double, double, double)? _quadratic(List<double> ts, List<double> xs) {
  // Normal equations of x = a + b t + c t², solved by Cramer's rule.
  final s = List<double>.filled(5, 0);
  final y = List<double>.filled(3, 0);
  for (var i = 0; i < ts.length; i++) {
    var power = 1.0;
    for (var k = 0; k < 5; k++) {
      s[k] += power;
      if (k < 3) y[k] += xs[i] * power;
      power *= ts[i];
    }
  }
  final [s0, s1, s2, s3, s4] = s;
  final [y0, y1, y2] = y;
  double det(
    double a,
    double b,
    double c,
    double d,
    double e,
    double f,
    double g,
    double h,
    double k,
  ) =>
      a * (e * k - f * h) - b * (d * k - f * g) + c * (d * h - e * g);
  final d = det(s0, s1, s2, s1, s2, s3, s2, s3, s4);
  if (d.abs() < 1e-9) return null;
  return (
    det(y0, s1, s2, y1, s2, s3, y2, s3, s4) / d,
    det(s0, y0, s2, s1, y1, s3, s2, y2, s4) / d,
    det(s0, s1, y0, s1, s2, y1, s2, s3, y2) / d,
  );
}
