import 'dart:typed_data';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/access_key.dart';
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/cipher.dart';
import 'package:eid_icao/src/exceptions.dart';
import 'package:eid_icao/src/secure_messaging.dart';

/// Basic Access Control, ICAO 9303 part 11: mutual authentication from the
/// MRZ, then secure messaging in 3DES.
///
/// [terminalNonce] and [terminalKey] are drawn at random unless given, for
/// tests. Throws an [IcaoAccessException] when the chip refuses [key].
Future<SecureMessaging> performBac(
  CardChannel raw,
  IcaoMrzKey key, {
  Uint8List? terminalNonce,
  Uint8List? terminalKey,
}) async {
  const cipher = SymmetricCipher.tripleDes;
  final seed = key.bacSeed;
  final encryptionKey = cipher.deriveKey(seed, 1);
  final macKey = cipher.deriveKey(seed, 2);

  final challenge = await raw.send(CommandApdu(0x00, 0x84, 0x00, 0x00, le: 8));
  if (!challenge.isSuccess || challenge.data.length != 8) {
    throw IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'GET CHALLENGE failed',
      statusWord: challenge.statusWord,
    );
  }
  final chipNonce = challenge.data;
  final nonce = terminalNonce ?? randomBytes(8);
  final keyPart = terminalKey ?? randomBytes(16);

  final cryptogram = cipher.encrypt(
    encryptionKey,
    concat([nonce, chipNonce, keyPart]),
  );
  final response = await raw.send(CommandApdu(
    0x00,
    0x82,
    0x00,
    0x00,
    data: concat([cryptogram, cipher.macPadded(macKey, cryptogram)]),
    le: 40,
  ));
  if (!response.isSuccess) {
    throw IcaoAccessException(
      IcaoAccessFailure.wrongKey,
      'The chip refused the MRZ',
      statusWord: response.statusWord,
    );
  }

  final answer = response.data;
  if (answer.length != 40) {
    throw const IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'EXTERNAL AUTHENTICATE answered with the wrong length',
    );
  }
  final chipCryptogram = Uint8List.sublistView(answer, 0, 32);
  if (!sameBytes(
    cipher.macPadded(macKey, chipCryptogram),
    Uint8List.sublistView(answer, 32),
  )) {
    throw const IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'The chip cryptogram fails its MAC',
    );
  }
  final plain = cipher.decrypt(encryptionKey, chipCryptogram);
  if (!sameBytes(plain.sublist(0, 8), chipNonce) ||
      !sameBytes(plain.sublist(8, 16), nonce)) {
    throw const IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'The chip did not return the nonces',
    );
  }

  final sessionSeed = xorBytes(keyPart, plain.sublist(16));
  return SecureMessaging(
    raw,
    cipher: cipher,
    encryptionKey: cipher.deriveKey(sessionSeed, 1),
    macKey: cipher.deriveKey(sessionSeed, 2),
    ssc: concat([chipNonce.sublist(4), nonce.sublist(4)]),
  );
}
