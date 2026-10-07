// ignore_for_file: avoid_print

import 'package:eid_icao/eid_icao.dart';
import 'package:eid_icao/testing.dart';

/// Reads a document and prints who it belongs to.
///
/// The transport comes from an adapter package. In a Flutter application
/// with a contactless PC/SC reader, that is `eid_ccid`:
///
/// ```dart
/// final readers = await CcidTransport.listReaders();
/// final transport = await CcidTransport.connect(readers.first);
/// await printDocument(transport, IcaoAccessKey.can('123456'));
/// await transport.disconnect();
/// ```
Future<void> printDocument(CardTransport transport, IcaoAccessKey key) async {
  final document = await IcaoReader(transport).read(access: key);
  final mrz = document.mrz;

  print('${mrz.firstNames} ${mrz.lastName}, ${mrz.nationality}');
  print('Born ${mrz.birthDate}');
  print('Document ${mrz.documentNumber}, valid until ${mrz.expiryDate}');
  print('Face: ${document.face}');
  print('Photo to show: ${document.face?.displayFormat?.name}, '
      '${document.photo?.length} bytes');
  print('Signed by: ${document.passiveAuthentication?.documentSigner}');
  print('Chip proof: ${document.authenticity?.name}');
}

/// Reads the simulated chip, which needs no reader.
Future<void> main() async {
  final chip = SimulatedIcaoChip();
  await printDocument(chip, chip.canKey);
}
