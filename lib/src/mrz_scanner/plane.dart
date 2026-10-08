import 'dart:typed_data';

/// A level grey image, rows packed, with its summed area table: the mean of
/// any box, fractional edges included, in constant time.
final class GreyPlane {
  /// The plane of [width] by [height] in [pixels].
  GreyPlane(this.width, this.height, this.pixels)
      : table = _summedAreas(width, height, pixels);

  /// The width.
  final int width;

  /// The height.
  final int height;

  /// The pixels, one byte each.
  final Uint8List pixels;

  /// The sums of every box from the top left corner: (width + 1) by
  /// (height + 1), a row and a column of zeros first.
  ///
  /// 32 bits hold every frame up to eight million pixels.
  final Int32List table;

  /// The plane [factor] times smaller each way, each pixel the mean of the
  /// box it covers.
  GreyPlane shrink(int factor) {
    if (factor <= 1) return this;
    final w = width ~/ factor;
    final h = height ~/ factor;
    final out = Uint8List(w * h);
    final area = factor * factor;
    final stride = width + 1;
    for (var y = 0; y < h; y++) {
      final top = y * factor * stride;
      final bottom = (y + 1) * factor * stride;
      for (var x = 0; x < w; x++) {
        final left = x * factor;
        final right = left + factor;
        final sum = table[bottom + right] -
            table[bottom + left] -
            table[top + right] +
            table[top + left];
        out[y * w + x] = sum ~/ area;
      }
    }
    return GreyPlane(w, h, out);
  }

  /// The sum of the integer box [x0], [y0] to [x1], [y1], ends excluded.
  int boxSum(int x0, int y0, int x1, int y1) {
    final stride = width + 1;
    return table[y1 * stride + x1] -
        table[y1 * stride + x0] -
        table[y0 * stride + x1] +
        table[y0 * stride + x0];
  }

  /// The mean grey of the box centred on ([x], [y]), [halfWidth] and
  /// [halfHeight] from its centre to its edges, in pixel units where pixel
  /// (i, j) spans [i, i + 1) by [j, j + 1).
  ///
  /// A box under a pixel is widened to one pixel: the mean then reads as a
  /// bilinear sample.
  double boxMean(double x, double y, double halfWidth, double halfHeight) {
    final hw = halfWidth < 0.5 ? 0.5 : halfWidth;
    final hh = halfHeight < 0.5 ? 0.5 : halfHeight;
    final x0 = x - hw;
    final x1 = x + hw;
    final y0 = y - hh;
    final y1 = y + hh;
    final sum = _at(x1, y1) - _at(x0, y1) - _at(x1, y0) + _at(x0, y0);
    return sum / (4 * hw * hh);
  }

  // The table between its entries, bilinear: boxes with fractional edges.
  double _at(double x, double y) {
    final maxX = width.toDouble();
    final maxY = height.toDouble();
    final cx = x < 0 ? 0.0 : (x > maxX ? maxX : x);
    final cy = y < 0 ? 0.0 : (y > maxY ? maxY : y);
    var ix = cx.toInt();
    var iy = cy.toInt();
    if (ix >= width) ix = width - 1;
    if (iy >= height) iy = height - 1;
    final fx = cx - ix;
    final fy = cy - iy;
    final stride = width + 1;
    final i = iy * stride + ix;
    final top = table[i] + (table[i + 1] - table[i]) * fx;
    final bottom =
        table[i + stride] + (table[i + stride + 1] - table[i + stride]) * fx;
    return top + (bottom - top) * fy;
  }
}

Int32List _summedAreas(int width, int height, Uint8List pixels) {
  final stride = width + 1;
  final table = Int32List(stride * (height + 1));
  for (var y = 0; y < height; y++) {
    var row = 0;
    final from = y * width;
    final above = y * stride;
    final at = above + stride;
    for (var x = 0; x < width; x++) {
      row += pixels[from + x];
      table[at + x + 1] = table[above + x + 1] + row;
    }
  }
  return table;
}
