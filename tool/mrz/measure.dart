// Measures the recognizer on the images of tool/mrz/make_test_images.py:
//
//     dart run tool/mrz/measure.dart out/
//
// A reading is right, wrong (valid yet not the truth: the worst case),
// invalid (the check digits caught it) or missing (no zone found).
import 'dart:io';

import 'package:eid_icao/eid_icao.dart';
import 'package:eid_icao/mrz_scanner.dart';

import 'pgm.dart';

void main(List<String> args) {
  final folder = Directory(args.isEmpty ? 'out' : args.first);
  final verbose = args.contains('-v');
  final files = folder
      .listSync()
      .whereType<File>()
      .where((f) => f.path.endsWith('.pgm'))
      .toList()
    ..sort((a, b) => a.path.compareTo(b.path));
  var right = 0;
  var wrong = 0;
  var wrongKey = 0;
  var invalid = 0;
  var missing = 0;
  var corrected = 0;
  final watch = Stopwatch();
  for (final file in files) {
    final truth = File(file.path.replaceAll('.pgm', '.txt')).readAsStringSync();
    final image = readPgm(file.readAsBytesSync());
    watch.start();
    final reading = const MrzRecognizer().read(image);
    watch.stop();
    final String verdict;
    if (reading == null) {
      missing++;
      verdict = 'missing';
    } else if (!reading.isValid) {
      invalid++;
      verdict = 'invalid';
    } else if (reading.text == truth) {
      right++;
      if (reading.corrections > 0) corrected++;
      verdict = 'right';
    } else {
      wrong++;
      final read = reading.mrz!;
      final real = IcaoMrz.parse(truth);
      final keyWrong = read.documentNumber != real.documentNumber ||
          read.birthDate != real.birthDate ||
          read.expiryDate != real.expiryDate;
      if (keyWrong) wrongKey++;
      verdict = keyWrong ? 'WRONG KEY' : 'WRONG';
    }
    if (verbose && verdict != 'right') {
      stdout.writeln('${file.path}: $verdict');
      if (reading != null) stdout.writeln('${reading.text}\n---\n$truth\n');
    }
  }
  final n = files.length;
  String share(int k) => '$k (${(k * 100 / n).toStringAsFixed(1)} %)';
  stdout
    ..writeln('images   $n')
    ..writeln('right    ${share(right)}, $corrected by check digits')
    ..writeln('wrong    ${share(wrong)}, ${share(wrongKey)} in the key')
    ..writeln('invalid  ${share(invalid)}')
    ..writeln('missing  ${share(missing)}')
    ..writeln('time     ${watch.elapsedMilliseconds ~/ n} ms an image');
}
