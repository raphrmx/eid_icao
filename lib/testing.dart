/// A passport or identity card chip in memory, to test an application
/// without a document or reader.
///
/// ```dart
/// import 'package:eid_icao/eid_icao.dart';
/// import 'package:eid_icao/testing.dart';
///
/// final chip = SimulatedIcaoChip();
/// final document = await IcaoReader(chip).read(access: chip.canKey);
/// ```
library;

export 'src/testing/simulated_icao_chip.dart';
export 'src/testing/specimen_photo.dart';
