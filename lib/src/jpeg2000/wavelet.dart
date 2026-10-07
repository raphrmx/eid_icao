import 'dart:typed_data';

/// A rectangle on a sample grid, from ([x0], [y0]) included to ([x1], [y1])
/// excluded.
final class Rect {
  /// The rectangle.
  const Rect(this.x0, this.y0, this.x1, this.y1);

  /// Its first column.
  final int x0;

  /// Its first row.
  final int y0;

  /// The column after its last.
  final int x1;

  /// The row after its last.
  final int y1;

  /// Its width, or 0.
  int get width => x1 > x0 ? x1 - x0 : 0;

  /// Its height, or 0.
  int get height => y1 > y0 ? y1 - y0 : 0;
}

// The lifting steps of the 9-7 filter, ITU-T T.800 table F.4.
const _alpha = -1.586134342059924;
const _beta = -0.052980118572961;
const _gamma = 0.882911075530934;
const _delta = 0.443506852043971;
const _k = 1.230174104914001;

/// Rebuilds a tile-component from its subbands, T.800 annex F.
///
/// [samples] holds, [stride] apart, the subbands of each [resolutions]
/// level as T.800 lays them out before the interleaving: for resolution r,
/// the lower resolution at the top left, the horizontally high-pass bands to
/// its right, the vertically high-pass ones below. [reversible] picks the
/// 5-3 filter, else the 9-7.
void inverseWavelet(
  Float64List samples,
  int stride,
  List<Rect> resolutions,
  bool reversible,
) {
  var longest = 0;
  for (final r in resolutions) {
    if (r.width > longest) longest = r.width;
    if (r.height > longest) longest = r.height;
  }
  final line = Float64List(longest);
  for (var level = 1; level < resolutions.length; level++) {
    final rect = resolutions[level];
    final lower = resolutions[level - 1];
    final width = rect.width;
    final height = rect.height;
    if (width == 0 || height == 0) continue;
    final xOdd = rect.x0 & 1;
    final yOdd = rect.y0 & 1;
    final lowWidth = lower.width;
    final lowHeight = lower.height;
    for (var y = 0; y < height; y++) {
      final row = y * stride;
      for (var i = 0; i < lowWidth; i++) {
        line[2 * i + xOdd] = samples[row + i];
      }
      for (var i = 0; i < width - lowWidth; i++) {
        line[2 * i + 1 - xOdd] = samples[row + lowWidth + i];
      }
      _synthesize(line, width, xOdd, reversible);
      for (var i = 0; i < width; i++) {
        samples[row + i] = line[i];
      }
    }
    for (var x = 0; x < width; x++) {
      for (var i = 0; i < lowHeight; i++) {
        line[2 * i + yOdd] = samples[i * stride + x];
      }
      for (var i = 0; i < height - lowHeight; i++) {
        line[2 * i + 1 - yOdd] = samples[(lowHeight + i) * stride + x];
      }
      _synthesize(line, height, yOdd, reversible);
      for (var i = 0; i < height; i++) {
        samples[i * stride + x] = line[i];
      }
    }
  }
}

// One dimensional synthesis of the n interleaved samples of x, the first of
// which is high-pass when odd is 1, with symmetric extension at both ends.
void _synthesize(Float64List x, int n, int odd, bool reversible) {
  if (n == 1) {
    if (odd == 1) {
      x[0] = reversible ? (x[0] / 2).truncateToDouble() : x[0] / 2;
    }
    return;
  }
  double at(int i) => x[i < 0 ? -i : (i >= n ? 2 * (n - 1) - i : i)];
  final low = odd;
  final high = 1 - odd;
  if (reversible) {
    for (var i = low; i < n; i += 2) {
      x[i] -= ((at(i - 1) + at(i + 1) + 2) / 4).floorToDouble();
    }
    for (var i = high; i < n; i += 2) {
      x[i] += ((at(i - 1) + at(i + 1)) / 2).floorToDouble();
    }
    return;
  }
  for (var i = low; i < n; i += 2) {
    x[i] *= _k;
  }
  for (var i = high; i < n; i += 2) {
    x[i] *= 1 / _k;
  }
  for (final (start, factor) in [
    (low, _delta),
    (high, _gamma),
    (low, _beta),
    (high, _alpha),
  ]) {
    for (var i = start; i < n; i += 2) {
      x[i] -= factor * (at(i - 1) + at(i + 1));
    }
  }
}
