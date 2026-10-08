import 'dart:typed_data';

import 'package:eid_icao/src/mrz_scanner/mrz_image.dart';

/// A binary PGM, P5, as made by Pillow.
MrzImage readPgm(Uint8List bytes) {
  var at = 0;
  String token() {
    while (bytes[at] == 0x20 || bytes[at] == 0x0A || bytes[at] == 0x0D) {
      at++;
    }
    final start = at;
    while (bytes[at] != 0x20 && bytes[at] != 0x0A && bytes[at] != 0x0D) {
      at++;
    }
    return String.fromCharCodes(bytes.sublist(start, at));
  }

  if (token() != 'P5') throw const FormatException('Not a binary PGM');
  final width = int.parse(token());
  final height = int.parse(token());
  token();
  at++;
  return MrzImage.luminance(
    width: width,
    height: height,
    bytes: Uint8List.sublistView(bytes, at, at + width * height),
  );
}
