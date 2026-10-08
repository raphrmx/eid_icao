import 'dart:math' as math;
import 'dart:typed_data';

import 'package:eid_icao/src/mrz.dart';
import 'package:eid_icao/src/mrz_scanner/classifier.dart';
import 'package:eid_icao/src/mrz_scanner/decoder.dart';
import 'package:eid_icao/src/mrz_scanner/glyphs.dart';
import 'package:eid_icao/src/mrz_scanner/layout.dart';
import 'package:eid_icao/src/mrz_scanner/locate.dart';
import 'package:eid_icao/src/mrz_scanner/mrz_image.dart';
import 'package:eid_icao/src/mrz_scanner/plane.dart';

/// A point of an image, in pixels from its top left corner once level.
typedef MrzPoint = ({double x, double y});

/// A zone read from one image: the text, how sure the reading is, where the
/// zone lies.
final class MrzReading {
  MrzReading._({
    required this.text,
    required this.mrz,
    required this.corrections,
    required this.margin,
    required this.corners,
    required this.upsideDown,
    required this.scores,
  });

  /// The zone as read, one line per row.
  final String text;

  /// The zone parsed, or null when the text read is no zone.
  final IcaoMrz? mrz;

  /// How many characters were read again to satisfy the check digits: a
  /// second choice where the first broke a check digit.
  final int corrections;

  /// The smallest lead of a character over the next one it could be, as
  /// the natural logarithm of their odds: under 1, a near tie.
  final double margin;

  /// The corners of the zone, in the image once level (see [MrzImage]):
  /// top left, top right, bottom right, bottom left.
  final List<MrzPoint> corners;

  /// Whether the document was upside down.
  final bool upsideDown;

  /// How likely each cell holds each character, as natural logarithms,
  /// lines run together.
  final List<Float32List> scores;

  /// Whether every check digit holds and the dates are dates: a reading
  /// to trust.
  bool get isValid {
    final mrz = this.mrz;
    return mrz != null &&
        mrz.isValid &&
        mrz.birthDate != null &&
        mrz.expiryDate != null;
  }

  @override
  String toString() => 'MrzReading(${isValid ? 'valid' : 'invalid'}, '
      '$corrections corrected)';
}

/// Reads the machine readable zone of a passport, an identity card or a
/// visa in an image, without any other library: OCR-B glyphs matched
/// against the cells of the zone, check digits putting near ties right.
///
/// ```dart
/// final reading = const MrzRecognizer().read(image);
/// if (reading != null && reading.isValid) {
///   final key = IcaoAccessKey.fromMrz(reading.text);
/// }
/// ```
///
/// One image may misread a character a check digit cannot catch, as in a
/// name: an [MrzScanner] waits for frames that agree.
final class MrzRecognizer {
  /// A recognizer.
  const MrzRecognizer();

  /// The zone in [image], or null when none is found.
  ///
  /// A document upside down is read too. The reading may fail its check
  /// digits: see [MrzReading.isValid].
  MrzReading? read(MrzImage image) {
    final width = image.uprightWidth;
    final height = image.uprightHeight;
    final pixels = image.upright();
    final plane = GreyPlane(width, height, pixels);
    final upright = _read(plane, upsideDown: false);
    if (upright != null && upright.isValid) return upright;
    final turned = Uint8List(pixels.length);
    for (var i = 0, j = pixels.length - 1; j >= 0; i++, j--) {
      turned[i] = pixels[j];
    }
    final flipped = _read(GreyPlane(width, height, turned), upsideDown: true);
    if (flipped != null && (flipped.isValid || upright == null)) {
      return flipped;
    }
    return upright;
  }

  MrzReading? _read(GreyPlane plane, {required bool upsideDown}) {
    final layout = locate(plane);
    if (layout == null) return null;
    final scores = [
      for (final line in layout.cells)
        for (final cell in line) classify(sampleCell(plane, cell)),
    ];
    final decoded = decode(layout.format, scores);
    var corners = _corners(layout);
    if (upsideDown) {
      corners = [
        for (final p in corners) (x: plane.width - p.x, y: plane.height - p.y),
      ];
    }
    return MrzReading._(
      text: decoded.text,
      mrz: decoded.mrz,
      corrections: decoded.replaced.length,
      margin: decoded.margin,
      corners: corners,
      upsideDown: upsideDown,
      scores: scores,
    );
  }
}

List<MrzPoint> _corners(MrzLayout layout) {
  MrzPoint corner(CellGeometry cell, double side, double up) {
    final ux = math.cos(cell.angle);
    final uy = math.sin(cell.angle);
    final along = side * cell.pitch / 2;
    final down = -up * cell.height;
    return (
      x: cell.x + along * ux - down * uy,
      y: cell.y + along * uy + down * ux,
    );
  }

  final top = layout.cells.first;
  final bottom = layout.cells.last;
  return [
    corner(top.first, -1, 1.25),
    corner(top.last, 1, 1.25),
    corner(bottom.last, 1, -0.25),
    corner(bottom.first, -1, -0.25),
  ];
}
