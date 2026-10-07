import 'dart:convert';
import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart';
import 'package:eid_icao/eid_icao.dart';
import 'package:eid_icao/src/jpeg2000/jpeg2000.dart';
import 'package:eid_icao/testing.dart';
import 'package:test/test.dart';

import 'jpeg2000_fixtures.dart';

const _pngSignature = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];

Uint8List _image(String name) => base64Decode(
    jpeg2000Fixtures.firstWhere((fixture) => fixture.name == name).image);

void main() {
  group('decodeJpeg2000', () {
    for (final fixture in jpeg2000Fixtures) {
      test('decodes as OpenJPEG does: ${fixture.name}', () {
        final image = decodeJpeg2000(base64Decode(fixture.image));
        expect(
          (image.width, image.height, image.channels),
          (fixture.width, fixture.height, fixture.channels),
        );
        if (fixture.exact) {
          expect(sha256.convert(image.pixels).toString(), fixture.expected);
        } else {
          // Lossy images round once more or less.
          final expected = base64Decode(fixture.expected);
          expect(image.pixels.length, expected.length);
          var worst = 0;
          for (var i = 0; i < expected.length; i++) {
            worst = max(worst, (image.pixels[i] - expected[i]).abs());
          }
          expect(worst, lessThanOrEqualTo(1));
        }
      });
    }

    test('decodes the JPEG 2000 specimen photo', () {
      final image = decodeJpeg2000(specimenPhotoJpeg2000);
      expect((image.width, image.height, image.channels), (200, 260, 3));
    });

    test('raises only FormatException on truncated or corrupted input', () {
      final random = Random(3);
      for (final name in [
        'every code-block mode',
        'packet headers in PPM',
        'tile-parts',
        'palette',
        'sYCC, chroma at half size',
      ]) {
        final sample = _image(name);
        void attempt(Uint8List bytes) {
          try {
            decodeJpeg2000(bytes);
          } on FormatException catch (error) {
            // Any other error would come out as 'Malformed data (...)'.
            expect(error.message, isNot(startsWith('Malformed data (')));
          }
        }

        for (var length = 0; length < sample.length; length += 13) {
          attempt(Uint8List.sublistView(sample, 0, length));
        }
        for (var i = 0; i < 150; i++) {
          final corrupted = Uint8List.fromList(sample);
          for (var k = random.nextInt(4); k >= 0; k--) {
            final at = random.nextBool()
                ? random.nextInt(min(160, corrupted.length))
                : random.nextInt(corrupted.length);
            corrupted[at] = random.nextInt(256);
          }
          attempt(corrupted);
        }
      }
    });

    test('turns down an image larger than maxPixels', () {
      expect(
        () => decodeJpeg2000(_image('lossless 5-3 RGB'), maxPixels: 1000),
        throwsA(isA<FormatException>()
            .having((e) => e.message, 'message', contains('image size'))),
      );
    });

    test('turns down high throughput code-blocks, which part 1 lacks', () {
      final codestream =
          Uint8List.fromList(_image('bare codestream with odd offsets'));
      for (var i = 0; i + 1 < codestream.length; i++) {
        if (codestream[i] == 0xFF && codestream[i + 1] == 0x52) {
          // Scod, SGcod, then levels, width, height: the style.
          codestream[i + 12] |= 0x40;
          break;
        }
      }
      expect(
        () => decodeJpeg2000(codestream),
        throwsA(isA<FormatException>()
            .having((e) => e.message, 'message', contains('high throughput'))),
      );
    });
  });

  group('IcaoImage', () {
    test('shows a JPEG 2000 image as PNG', () {
      final image = IcaoImage.sniff(specimenPhotoJpeg2000);
      expect(image.format, IcaoImageFormat.jpeg2000);
      expect((image.width, image.height), (200, 260));
      expect(image.displayFormat, IcaoImageFormat.png);
      expect(image.displayBytes?.sublist(0, 8), _pngSignature);
    });

    test('shows a JPEG as it is', () {
      final image = IcaoImage.sniff(specimenPhoto);
      expect(image.displayFormat, IcaoImageFormat.jpeg);
      expect(image.displayBytes, same(image.bytes));
    });

    test('has nothing to show for a JPEG 2000 image it cannot decode', () {
      final broken = Uint8List.sublistView(specimenPhotoJpeg2000, 0, 200);
      final image = IcaoImage.sniff(broken);
      expect(image.format, IcaoImageFormat.jpeg2000);
      expect(image.displayBytes, isNull);
      expect(image.displayFormat, isNull);
    });
  });

  group('IcaoDocument.photo', () {
    for (final encoding in IcaoFaceEncoding.values) {
      test('is a PNG for a JPEG 2000 face in ${encoding.name}', () async {
        final chip = SimulatedIcaoChip(
          photo: specimenPhotoJpeg2000,
          faceEncoding: encoding,
        );
        final document = await IcaoReader(chip).read(access: chip.canKey);
        expect(document.face?.format, IcaoImageFormat.jpeg2000);
        expect(document.face?.bytes, specimenPhotoJpeg2000);
        expect(document.photo?.sublist(0, 8), _pngSignature);
      });
    }

    test('is the JPEG itself for a JPEG face', () async {
      final chip = SimulatedIcaoChip();
      final document = await IcaoReader(chip).read(access: chip.canKey);
      expect(document.photo, specimenPhoto);
    });
  });
}
