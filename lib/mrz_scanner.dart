/// Reads the machine readable zone of passports, identity cards and visas
/// in a camera frame or a photo, in pure Dart: the key that opens their chip,
/// without typing it.
///
/// An [MrzRecognizer] reads one image; an [MrzScanner] reads the frames of
/// a camera until enough of them agree.
///
/// ```dart
/// import 'package:eid_icao/mrz_scanner.dart';
///
/// final scanner = MrzScanner();
/// final result = scanner.add(MrzImage.luminance(
///   width: frame.width,
///   height: frame.height,
///   bytes: frame.bytes,
/// ));
/// if (result != null) await IcaoReader(transport).read(access: result.accessKey);
/// ```
library;

export 'src/mrz_scanner/mrz_image.dart';
export 'src/mrz_scanner/recognizer.dart'
    show MrzPoint, MrzReading, MrzRecognizer;
export 'src/mrz_scanner/scanner.dart';
