import 'dart:typed_data';

import 'package:eid_icao/src/jpeg2000/jpeg2000.dart';
import 'package:eid_icao/src/png.dart';

/// The encodings of images on a chip.
enum IcaoImageFormat {
  /// JPEG, which Flutter's `Image.memory` shows.
  jpeg,

  /// JPEG 2000, a JP2 file or a bare codestream, which Flutter does not
  /// decode: `IcaoImage.displayBytes` holds it as PNG.
  jpeg2000,

  /// PNG.
  png,

  /// Something else, such as a WSQ fingerprint.
  other,
}

/// An image read from the chip: the face, a signature, a scanned page.
final class IcaoImage {
  /// [bytes] encoded as [format], [width] by [height] pixels when known.
  ///
  /// A JPEG 2000 image is decoded here, for [displayBytes].
  IcaoImage(this.bytes, this.format, {this.width, this.height})
      : displayBytes = switch (format) {
          IcaoImageFormat.jpeg || IcaoImageFormat.png => bytes,
          IcaoImageFormat.jpeg2000 => _pngOf(bytes),
          IcaoImageFormat.other => null,
        };

  /// Recognises [bytes] by their first bytes and reads their size.
  factory IcaoImage.sniff(Uint8List bytes) => sniffImage(bytes);

  /// The image as the chip holds it, encoded as [format].
  final Uint8List bytes;

  /// The image as JPEG or PNG, which Flutter's `Image.memory` and browsers
  /// show: [bytes] themselves for a JPEG or a PNG, the image converted to
  /// PNG for JPEG 2000. Null for another format, or a JPEG 2000 image that
  /// cannot be decoded.
  final Uint8List? displayBytes;

  /// The format of [displayBytes]: JPEG or PNG, null without them.
  IcaoImageFormat? get displayFormat => displayBytes == null
      ? null
      : (format == IcaoImageFormat.jpeg
          ? IcaoImageFormat.jpeg
          : IcaoImageFormat.png);

  /// Its encoding.
  final IcaoImageFormat format;

  /// Its width in pixels, when known.
  final int? width;

  /// Its height in pixels, when known.
  final int? height;

  /// The usual MIME type: `image/jpeg`, `image/jp2`, `image/png`.
  String get mimeType => switch (format) {
        IcaoImageFormat.jpeg => 'image/jpeg',
        IcaoImageFormat.jpeg2000 => 'image/jp2',
        IcaoImageFormat.png => 'image/png',
        IcaoImageFormat.other => 'application/octet-stream',
      };

  @override
  String toString() => 'IcaoImage(${format.name}, ${width ?? '?'}x'
      '${height ?? '?'}, ${bytes.length} bytes)';
}

/// [bytes] as an image, their format and size read from their first bytes,
/// else [format], [width] and [height].
IcaoImage sniffImage(
  Uint8List bytes, {
  IcaoImageFormat format = IcaoImageFormat.other,
  int? width,
  int? height,
}) {
  final sniffed = imageFormatOf(bytes);
  final known = sniffed == IcaoImageFormat.other ? format : sniffed;
  final size = _imageSize(bytes, sniffed);
  return IcaoImage(
    bytes,
    known,
    width: size?.$1 ?? width,
    height: size?.$2 ?? height,
  );
}

// The JPEG 2000 image in bytes as PNG, or null if it cannot be decoded.
Uint8List? _pngOf(Uint8List bytes) {
  try {
    final image = decodeJpeg2000(bytes);
    return encodePng(image.width, image.height, image.channels, image.pixels);
  } on FormatException {
    return null;
  }
}

/// The format of [bytes], from their signature.
IcaoImageFormat imageFormatOf(List<int> bytes) {
  bool startsWith(List<int> prefix) {
    if (bytes.length < prefix.length) return false;
    for (var i = 0; i < prefix.length; i++) {
      if (bytes[i] != prefix[i]) return false;
    }
    return true;
  }

  if (startsWith(const [0xFF, 0xD8, 0xFF])) return IcaoImageFormat.jpeg;
  if (startsWith(const [0, 0, 0, 0x0C, 0x6A, 0x50, 0x20, 0x20]) ||
      startsWith(const [0xFF, 0x4F, 0xFF, 0x51])) {
    return IcaoImageFormat.jpeg2000;
  }
  if (startsWith(const [0x89, 0x50, 0x4E, 0x47])) return IcaoImageFormat.png;
  return IcaoImageFormat.other;
}

int _u16(List<int> b, int i) => b[i] << 8 | b[i + 1];

int _u32(List<int> b, int i) =>
    b[i] << 24 | b[i + 1] << 16 | b[i + 2] << 8 | b[i + 3];

// Width and height read from the image header, or null.
(int, int)? _imageSize(Uint8List bytes, IcaoImageFormat format) {
  switch (format) {
    case IcaoImageFormat.jpeg:
      var i = 2;
      while (i + 9 < bytes.length) {
        if (bytes[i] != 0xFF) return null;
        final marker = bytes[i + 1];
        // SOF0 to SOF15, except DHT, JPG and DAC.
        if (marker >= 0xC0 &&
            marker <= 0xCF &&
            marker != 0xC4 &&
            marker != 0xC8 &&
            marker != 0xCC) {
          return (_u16(bytes, i + 7), _u16(bytes, i + 5));
        }
        i += 2 + _u16(bytes, i + 2);
      }
    case IcaoImageFormat.jpeg2000:
      // The SIZ marker, in a JP2 file or a bare codestream.
      for (var i = 0; i + 22 < bytes.length; i++) {
        if (bytes[i] == 0xFF && bytes[i + 1] == 0x51) {
          final width = _u32(bytes, i + 6) - _u32(bytes, i + 14);
          final height = _u32(bytes, i + 10) - _u32(bytes, i + 18);
          return (width, height);
        }
      }
    case IcaoImageFormat.png:
      if (bytes.length >= 24) return (_u32(bytes, 16), _u32(bytes, 20));
    case IcaoImageFormat.other:
  }
  return null;
}
