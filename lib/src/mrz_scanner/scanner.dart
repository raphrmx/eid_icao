import 'dart:typed_data';

import 'package:eid_icao/src/access_key.dart';
import 'package:eid_icao/src/mrz.dart';
import 'package:eid_icao/src/mrz_scanner/decoder.dart';
import 'package:eid_icao/src/mrz_scanner/mrz_image.dart';
import 'package:eid_icao/src/mrz_scanner/recognizer.dart';

/// A zone read and confirmed by several frames: ready to open the chip.
final class MrzScanResult {
  MrzScanResult._(this.text, this.mrz, this.frames);

  /// The zone, one line per row.
  final String text;

  /// The zone parsed: every check digit holds.
  final IcaoMrz mrz;

  /// The frames that read this zone.
  final int frames;

  /// The key that opens the chip, for BAC or PACE.
  IcaoAccessKey get accessKey => IcaoAccessKey.fromMrz(text);

  @override
  String toString() => 'MrzScanResult($frames frames)';
}

/// Reads the zone in the frames of a camera until enough of them agree.
///
/// A frame alone may misread a character no check digit covers, or two
/// that cancel out in the check digit: the scanner returns a zone once
/// [agreement] frames read it the same, each frame alone or the frames so
/// far together. The frames together also read a zone no single frame
/// reads whole, a reflection moving over the document.
///
/// ```dart
/// final scanner = MrzScanner();
/// await for (final frame in camera) {
///   final result = scanner.add(frame);
///   if (result != null) return result.accessKey;
/// }
/// ```
final class MrzScanner {
  /// A scanner that wants [agreement] frames to agree, keeping the last
  /// [memory] frames that found a zone.
  MrzScanner({
    this.agreement = 2,
    this.memory = 8,
    MrzRecognizer recognizer = const MrzRecognizer(),
  }) : _recognizer = recognizer {
    if (agreement < 1 || memory < agreement) {
      throw ArgumentError('agreement from 1 to memory');
    }
  }

  /// How many frames must read the same zone.
  final int agreement;

  /// How many of the last frames that found a zone count.
  final int memory;

  final MrzRecognizer _recognizer;
  final List<MrzReading> _readings = [];
  final List<String> _votes = [];

  /// The zone in the last frame that found one, read or not: to show where
  /// it is, or how far the reading got.
  MrzReading? get lastReading => _readings.isEmpty ? null : _readings.last;

  /// Reads [frame]; returns the zone once [agreement] frames agree, null
  /// until then.
  MrzScanResult? add(MrzImage frame) => addReading(_recognizer.read(frame));

  /// Counts a [reading] already made, as by an [MrzRecognizer] in another
  /// isolate; null for a frame without a zone.
  MrzScanResult? addReading(MrzReading? reading) {
    if (reading == null) return null;
    final last = lastReading;
    if (last != null && last.mrz?.format != reading.mrz?.format) reset();
    if (reading.mrz == null) return null;
    _readings.add(reading);
    if (_readings.length > memory) _readings.removeAt(0);

    final texts = <String>{};
    if (reading.isValid) texts.add(reading.text);
    if (_readings.length > 1) {
      final together = _together();
      if (together.isValid) texts.add(together.text);
    }
    _votes.addAll(texts);
    if (_votes.length > memory * 2) {
      _votes.removeRange(0, _votes.length - memory * 2);
    }
    for (final text in texts) {
      final count = _votes.where((vote) => vote == text).length;
      if (count >= agreement) {
        return MrzScanResult._(text, IcaoMrz.parse(text), count);
      }
    }
    return null;
  }

  /// Forgets the frames so far: for the next document.
  void reset() {
    _readings.clear();
    _votes.clear();
  }

  // The frames so far as one: the mean likelihood of each character.
  Decoded _together() {
    final format = _readings.first.mrz!.format;
    final cells = _readings.first.scores.length;
    final sums = [for (var i = 0; i < cells; i++) Float32List(37)];
    for (final reading in _readings) {
      for (var i = 0; i < cells; i++) {
        final scores = reading.scores[i];
        final sum = sums[i];
        for (var k = 0; k < sum.length; k++) {
          // A frame sure of a wrong character weighs no more than this.
          final score = scores[k] < -12 ? -12.0 : scores[k];
          sum[k] += score / _readings.length;
        }
      }
    }
    return decode(format, sums);
  }
}
