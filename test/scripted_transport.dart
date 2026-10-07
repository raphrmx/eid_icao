import 'dart:typed_data';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/bytes.dart';

/// Answers each command with the next scripted response, and records what it
/// was sent.
final class ScriptedTransport implements CardTransport {
  ScriptedTransport(List<String> responses)
      : _responses = responses.map(hexBytes).toList();

  final List<Uint8List> _responses;
  final List<String> sent = [];

  @override
  Future<Uint8List> transmit(Uint8List command) async {
    sent.add(hexString(command));
    if (_responses.isEmpty) {
      throw StateError('No response scripted for ${hexString(command)}');
    }
    return _responses.removeAt(0);
  }
}
