// Exports the cells the recognizer samples from the images of
// tool/mrz/make_test_images.py, with the character each holds: the training
// set of tool/mrz/train_glyph_model.py.
//
//     dart run tool/mrz/export_cells.dart train/ cells.bin
//
// Each record: the character's index in the alphabet, one byte, then the
// window and the correlations, float32 little endian.
import 'dart:io';
import 'dart:typed_data';

import 'package:eid_icao/src/mrz_scanner/glyphs.dart';
import 'package:eid_icao/src/mrz_scanner/locate.dart';
import 'package:eid_icao/src/mrz_scanner/ocrb_templates.dart';
import 'package:eid_icao/src/mrz_scanner/plane.dart';

import 'pgm.dart';

void main(List<String> args) {
  final files = Directory(args[0])
      .listSync()
      .whereType<File>()
      .where((f) => f.path.endsWith('.pgm'))
      .where((f) => File(f.path.replaceAll('.pgm', '.txt')).existsSync())
      .toList()
    ..sort((a, b) => a.path.compareTo(b.path));
  final out = File(args[1]).openSync(mode: FileMode.write);
  var images = 0;
  var cells = 0;
  for (final file in files) {
    final truth = File(file.path.replaceAll('.pgm', '.txt'))
        .readAsStringSync()
        .replaceAll('\n', '');
    final image = readPgm(file.readAsBytesSync());
    final pixels = image.upright();
    final turned = Uint8List.fromList(pixels.reversed.toList());
    for (final bytes in [pixels, turned]) {
      final plane = GreyPlane(image.uprightWidth, image.uprightHeight, bytes);
      final layout = locate(plane);
      if (layout == null) continue;
      final samples = [
        for (final line in layout.cells)
          for (final cell in line) sampleCell(plane, cell),
      ];
      if (samples.length != truth.length) continue;
      var agree = 0;
      for (var i = 0; i < samples.length; i++) {
        final c = samples[i].correlations;
        var best = 0;
        for (var k = 1; k < c.length; k++) {
          if (c[k] > c[best]) best = k;
        }
        if (ocrbAlphabet[best] == truth[i]) agree++;
      }
      // A layout off by a cell would teach the wrong characters.
      if (agree < samples.length * 0.75) continue;
      for (var i = 0; i < samples.length; i++) {
        final record = BytesBuilder()
          ..addByte(ocrbAlphabet.indexOf(truth[i]))
          ..add(samples[i].window.buffer.asUint8List())
          ..add(samples[i].correlations.buffer.asUint8List());
        out.writeFromSync(record.takeBytes());
        cells++;
      }
      images++;
      break;
    }
  }
  out.closeSync();
  stdout.writeln('$images of ${files.length} images, $cells cells');
}
