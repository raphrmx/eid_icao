@TestOn('vm')
library;

import 'dart:io';
import 'dart:math';
import 'dart:typed_data';

import 'package:eid_icao/src/png.dart';
import 'package:test/test.dart';

// The pixels of a PNG made by encodePng, unfiltered, through dart:io's
// inflate; the CRC of each chunk checked.
(int, int, int, Uint8List) _decode(Uint8List png) {
  final data = ByteData.sublistView(png);
  var at = 8;
  late int width;
  late int height;
  late int channels;
  final idat = BytesBuilder();
  while (at < png.length) {
    final length = data.getUint32(at);
    final type = String.fromCharCodes(png.sublist(at + 4, at + 8));
    final body = Uint8List.sublistView(png, at + 8, at + 8 + length);
    expect(data.getUint32(at + 8 + length),
        _crc(Uint8List.sublistView(png, at + 4, at + 8 + length)));
    if (type == 'IHDR') {
      width = data.getUint32(at + 8);
      height = data.getUint32(at + 12);
      channels = const {0: 1, 4: 2, 2: 3, 6: 4}[body[9]]!;
    } else if (type == 'IDAT') {
      idat.add(body);
    }
    at += 12 + length;
  }
  final raw = Uint8List.fromList(ZLibCodec().decode(idat.takeBytes()));
  final stride = width * channels;
  final pixels = Uint8List(stride * height);
  for (var y = 0; y < height; y++) {
    final filter = raw[y * (stride + 1)];
    for (var i = 0; i < stride; i++) {
      final a = i >= channels ? pixels[y * stride + i - channels] : 0;
      final b = y > 0 ? pixels[(y - 1) * stride + i] : 0;
      final c =
          y > 0 && i >= channels ? pixels[(y - 1) * stride + i - channels] : 0;
      final p = a + b - c;
      final paeth =
          (p - a).abs() <= (p - b).abs() && (p - a).abs() <= (p - c).abs()
              ? a
              : ((p - b).abs() <= (p - c).abs() ? b : c);
      final predicted = switch (filter) {
        0 => 0,
        1 => a,
        2 => b,
        3 => (a + b) >> 1,
        _ => paeth,
      };
      pixels[y * stride + i] =
          (raw[y * (stride + 1) + 1 + i] + predicted) & 0xFF;
    }
  }
  return (width, height, channels, pixels);
}

void _expectPixels(
    Uint8List png, int width, int height, int channels, Uint8List pixels) {
  final (w, h, c, decoded) = _decode(png);
  expect((w, h, c), (width, height, channels));
  expect(decoded, pixels);
}

int _crc(Uint8List bytes) {
  var c = 0xFFFFFFFF;
  for (final byte in bytes) {
    c ^= byte;
    for (var k = 0; k < 8; k++) {
      c = c & 1 != 0 ? 0xEDB88320 ^ (c >> 1) : c >> 1;
    }
  }
  return c ^ 0xFFFFFFFF;
}

void main() {
  final random = Random(5);

  for (var channels = 1; channels <= 4; channels++) {
    test('encodes $channels channels that decode back', () {
      const width = 61;
      const height = 47;
      final pixels = Uint8List(width * height * channels);
      for (var i = 0; i < pixels.length; i++) {
        pixels[i] = (i * 7 ~/ channels + random.nextInt(9)) & 0xFF;
      }
      final png = encodePng(width, height, channels, pixels);
      expect(png.sublist(1, 4), 'PNG'.codeUnits);
      _expectPixels(png, width, height, channels, pixels);
    });
  }

  test('encodes noise, runs and long matches across several blocks', () {
    const width = 400;
    const height = 300;
    final pixels = Uint8List(width * height * 3);
    for (var i = 0; i < pixels.length; i++) {
      pixels[i] = switch ((i ~/ 30000) % 3) {
        0 => random.nextInt(256),
        1 => 200,
        _ => (i ~/ 3) & 0xFF,
      };
    }
    final png = encodePng(width, height, 3, pixels);
    _expectPixels(png, width, height, 3, pixels);
  });

  test('encodes a single pixel', () {
    final pixels = Uint8List.fromList([1, 2, 3]);
    _expectPixels(encodePng(1, 1, 3, pixels), 1, 1, 3, pixels);
  });
}
