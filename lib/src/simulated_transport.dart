import 'package:eid_icao/src/certificate.dart';

/// Implemented by the simulated chip and its connections only: the CSCA
/// that signs them is trusted for them alone, never for a real document.
abstract interface class SimulatedTransport {
  /// The made-up CSCA of the simulated document.
  IcaoCertificate get simulatedCsca;
}
