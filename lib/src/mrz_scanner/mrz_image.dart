import 'dart:typed_data';

/// How far a frame is turned from upright: the quarter turns, clockwise,
/// that bring its text level.
enum MrzRotation {
  /// The text is already level.
  none,

  /// A quarter turn clockwise.
  clockwise90,

  /// A half turn.
  upsideDown,

  /// A quarter turn counter-clockwise.
  counterClockwise90,
}

/// A grey image: a camera frame, a photo of a document, a crop of either.
///
/// Takes a camera's luminance plane as it comes, its row stride included,
/// without a copy: the Y plane of a YUV frame on Android, the first plane
/// of a biplanar frame on iOS.
///
/// ```dart
/// final image = MrzImage.luminance(
///   width: 1280,
///   height: 720,
///   bytes: yPlane,
///   rowStride: 1280,
/// );
/// ```
final class MrzImage {
  /// A luminance plane of [width] by [height], one byte per pixel, rows
  /// [rowStride] bytes apart: [width] by default.
  ///
  /// Throws an [ArgumentError] when [bytes] is too short.
  MrzImage.luminance({
    required this.width,
    required this.height,
    required Uint8List bytes,
    int? rowStride,
    this.rotation = MrzRotation.none,
  })  : _bytes = bytes,
        _stride = rowStride ?? width {
    if (width <= 0 || height <= 0) {
      throw ArgumentError('An image has a positive size: $width by $height');
    }
    if (_stride < width || bytes.length < _stride * (height - 1) + width) {
      throw ArgumentError.value(
        bytes.length,
        'bytes',
        'Too short for $width by $height, rows $_stride bytes apart',
      );
    }
  }

  /// Four bytes per pixel, red first: the pixels of a canvas or of a
  /// decoded image.
  factory MrzImage.rgba({
    required int width,
    required int height,
    required Uint8List bytes,
    int? rowStride,
    MrzRotation rotation = MrzRotation.none,
  }) =>
      MrzImage._colour(width, height, bytes, rowStride, rotation, 0, 2);

  /// Four bytes per pixel, blue first: the frames of an iPhone or a Mac in
  /// their BGRA format.
  factory MrzImage.bgra({
    required int width,
    required int height,
    required Uint8List bytes,
    int? rowStride,
    MrzRotation rotation = MrzRotation.none,
  }) =>
      MrzImage._colour(width, height, bytes, rowStride, rotation, 2, 0);

  // The luminance of a colour image, ITU-R BT.601, in integers.
  factory MrzImage._colour(
    int width,
    int height,
    Uint8List bytes,
    int? rowStride,
    MrzRotation rotation,
    int red,
    int blue,
  ) {
    final stride = rowStride ?? width * 4;
    if (width <= 0 ||
        height <= 0 ||
        stride < width * 4 ||
        bytes.length < stride * (height - 1) + width * 4) {
      throw ArgumentError.value(
        bytes.length,
        'bytes',
        'Too short for $width by $height in four bytes per pixel',
      );
    }
    final grey = Uint8List(width * height);
    for (var y = 0; y < height; y++) {
      var from = y * stride;
      final row = y * width;
      for (var x = 0; x < width; x++, from += 4) {
        grey[row + x] = (bytes[from + red] * 77 +
                bytes[from + 1] * 150 +
                bytes[from + blue] * 29) >>
            8;
      }
    }
    return MrzImage.luminance(
      width: width,
      height: height,
      bytes: grey,
      rotation: rotation,
    );
  }

  /// The width of the frame as given, before [rotation].
  final int width;

  /// The height of the frame as given, before [rotation].
  final int height;

  /// How the frame is turned.
  final MrzRotation rotation;

  final Uint8List _bytes;
  final int _stride;

  /// The width once level.
  int get uprightWidth => _quarter ? height : width;

  /// The height once level.
  int get uprightHeight => _quarter ? width : height;

  bool get _quarter =>
      rotation == MrzRotation.clockwise90 ||
      rotation == MrzRotation.counterClockwise90;

  /// The pixels once level, rows packed, one byte each.
  ///
  /// The plane as given when it needs no turn and no repacking.
  Uint8List upright() {
    if (rotation == MrzRotation.none && _stride == width) {
      return Uint8List.sublistView(_bytes, 0, width * height);
    }
    final out = Uint8List(width * height);
    final w = uprightWidth;
    for (var y = 0; y < height; y++) {
      final row = y * _stride;
      for (var x = 0; x < width; x++) {
        final value = _bytes[row + x];
        final int index;
        switch (rotation) {
          case MrzRotation.none:
            index = y * w + x;
          case MrzRotation.clockwise90:
            index = x * w + (height - 1 - y);
          case MrzRotation.upsideDown:
            index = (height - 1 - y) * w + (width - 1 - x);
          case MrzRotation.counterClockwise90:
            index = (width - 1 - x) * w + y;
        }
        out[index] = value;
      }
    }
    return out;
  }
}
