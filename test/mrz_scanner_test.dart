import 'dart:math' as math;
import 'dart:typed_data';

import 'package:eid_icao/eid_icao.dart';
import 'package:eid_icao/mrz_scanner.dart';
import 'package:eid_icao/src/mrz_scanner/decoder.dart';
import 'package:eid_icao/src/mrz_scanner/ocrb_templates.dart';
import 'package:test/test.dart';

import 'support/mrz_render.dart';

// The specimens of ICAO Doc 9303.
const _passport = [
  'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<',
  'L898902C36UTO7408122F1204159ZE184226B<<<<<10',
];

const _card = [
  'I<UTOD231458907<<<<<<<<<<<<<<<',
  '7408122F1204159UTO<<<<<<<<<<<6',
  'ERIKSSON<<ANNA<MARIA<<<<<<<<<<',
];

MrzImage _image(
  List<String> lines, {
  double angle = 0,
  int noise = 0,
  MrzRotation rotation = MrzRotation.none,
}) {
  const width = 1600;
  const height = 700;
  final page = renderZone(
    lines,
    width: width,
    height: height,
    angle: angle,
    noise: noise,
  );
  return switch (rotation) {
    MrzRotation.none =>
      MrzImage.luminance(width: width, height: height, bytes: page),
    // The camera sees the page a quarter turn counter-clockwise: the page
    // stands up after a quarter turn clockwise.
    MrzRotation.clockwise90 => MrzImage.luminance(
        width: height,
        height: width,
        bytes: _turnCounterClockwise(page, width, height),
        rotation: rotation,
      ),
    _ => throw UnimplementedError(),
  };
}

Uint8List _turnCounterClockwise(Uint8List pixels, int width, int height) {
  final out = Uint8List(pixels.length);
  for (var y = 0; y < height; y++) {
    for (var x = 0; x < width; x++) {
      out[(width - 1 - x) * height + y] = pixels[y * width + x];
    }
  }
  return out;
}

Float32List _sure(String char) {
  final scores = Float32List(ocrbAlphabet.length)..fillRange(0, 37, -20);
  scores[ocrbAlphabet.indexOf(char)] = 0;
  return scores;
}

void main() {
  group('MrzRecognizer', () {
    const recognizer = MrzRecognizer();

    test('reads a passport', () {
      final reading = recognizer.read(_image(_passport))!;
      expect(reading.text, _passport.join('\n'));
      expect(reading.isValid, isTrue);
      expect(reading.upsideDown, isFalse);
      expect(reading.mrz!.format, IcaoMrzFormat.td3);
    });

    test('reads an identity card, slanted and noisy', () {
      final reading = recognizer.read(
        _image(_card, angle: 3 * math.pi / 180, noise: 20),
      )!;
      expect(reading.text, _card.join('\n'));
      expect(reading.mrz!.documentNumber, 'D23145890');
    });

    test('reads a document upside down', () {
      final reading = recognizer.read(_image(_card, angle: math.pi))!;
      expect(reading.text, _card.join('\n'));
      expect(reading.upsideDown, isTrue);
    });

    test('stands a sideways camera frame up', () {
      final reading = recognizer.read(
        _image(_passport, rotation: MrzRotation.clockwise90),
      )!;
      expect(reading.text, _passport.join('\n'));
    });

    test('finds nothing on a blank page', () {
      final page = Uint8List(640 * 480)..fillRange(0, 640 * 480, 200);
      expect(
        recognizer
            .read(MrzImage.luminance(width: 640, height: 480, bytes: page)),
        isNull,
      );
    });
  });

  group('decode', () {
    test('takes a second choice that a check digit asks for', () {
      final text = _passport.join();
      final scores = [for (final char in text.split('')) _sure(char)];
      // The document number's first digit read as 3, 8 a close second.
      const at = 44 + 3;
      scores[at] = _sure('3')..[ocrbAlphabet.indexOf('8')] = -0.4;
      final decoded = decode(IcaoMrzFormat.td3, scores);
      expect(decoded.text, _passport.join('\n'));
      expect(decoded.replaced, [at]);
      expect(decoded.isValid, isTrue);
    });

    test('keeps letters out of digit positions', () {
      final text = _passport.join();
      final scores = [for (final char in text.split('')) _sure(char)];
      // The birth date's first digit looks like an O more than a 0.
      const at = 44 + 13;
      scores[at] = _sure('O')..[ocrbAlphabet.indexOf('7')] = -3;
      expect(decode(IcaoMrzFormat.td3, scores).text, _passport.join('\n'));
    });
  });

  group('MrzScanner', () {
    test('waits for two frames that agree', () {
      final scanner = MrzScanner();
      final frame = _image(_card);
      expect(scanner.add(frame), isNull);
      final result = scanner.add(frame)!;
      expect(result.text, _card.join('\n'));
      expect(result.frames, 2);
      expect(
        (result.accessKey as IcaoMrzKey).documentNumber,
        'D23145890',
      );
    });

    test('forgets the frames of the last document', () {
      final scanner = MrzScanner()..add(_image(_card));
      scanner.reset();
      expect(scanner.lastReading, isNull);
      expect(scanner.add(_image(_card)), isNull);
    });

    test('wants agreement within memory', () {
      expect(() => MrzScanner(agreement: 0), throwsArgumentError);
      expect(() => MrzScanner(agreement: 3, memory: 2), throwsArgumentError);
    });
  });

  test('MrzImage refuses bytes too short', () {
    expect(
      () => MrzImage.luminance(width: 10, height: 10, bytes: Uint8List(50)),
      throwsArgumentError,
    );
  });
}
