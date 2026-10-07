import 'dart:typed_data';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/access_key.dart';
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/agreement.dart';
import 'package:eid_icao/src/crypto/cipher.dart';
import 'package:eid_icao/src/exceptions.dart';
import 'package:eid_icao/src/secure_messaging.dart';
import 'package:eid_icao/src/security_infos.dart';
import 'package:eid_icao/src/tlv.dart';

/// What PACE leaves behind: the secure messaging session and, after Chip
/// Authentication Mapping, what checks the chip.
final class PaceResult {
  /// The outcome of a PACE run.
  const PaceResult(
    this.session, {
    required this.info,
    required this.chipMappingKey,
    this.chipAuthenticationData,
  });

  /// The secure messaging session, counter at zero.
  final SecureMessaging session;

  /// The variant run.
  final PaceInfo info;

  /// The chip's encoded mapping public key.
  final Uint8List chipMappingKey;

  /// The chip's authentication data, after Chip Authentication Mapping.
  final Uint8List? chipAuthenticationData;
}

/// Runs PACE, ICAO 9303 part 11, with Generic Mapping or Chip
/// Authentication Mapping, over [raw] before any secure messaging.
///
/// [mappingKey] and [agreementKey], the terminal's private keys, are drawn
/// at random unless given, for tests. Throws an [IcaoAccessException] when
/// the chip refuses [key].
Future<PaceResult> performPace(
  CardChannel raw,
  IcaoAccessKey key,
  PaceInfo info,
  Object domainParameters, {
  BigInt? mappingKey,
  BigInt? agreementKey,
}) async {
  final cipher = info.cipher!;
  final oid = info.objectIdentifier;
  final base = Agreement.over(domainParameters);

  final setUp = await raw.send(CommandApdu(
    0x00,
    0x22,
    0xC1,
    0xA4,
    data: concat([
      tlv(0x80, encodeObjectIdentifier(oid)),
      tlv(0x83, [key.paceReference]),
      if (info.parameterId case final id?) tlv(0x84, [id]),
    ]),
  ));
  if (!setUp.isSuccess) {
    throw IcaoAccessException(
      IcaoAccessFailure.unsupported,
      'The chip refused to start PACE',
      statusWord: setUp.statusWord,
    );
  }

  final passwordKey = cipher.deriveKey(key.paceSecret, 3);
  final encryptedNonce = await _step(raw, const [], 0x80);
  final nonce = unsignedBigInt(cipher.decrypt(passwordKey, encryptedNonce));

  final (mappingPrivate, mappingPublic) = mappingKey == null
      ? base.generateKeyPair()
      : (mappingKey, base.publicKey(mappingKey));
  final chipMapping = await _step(raw, tlv(0x81, mappingPublic), 0x82);
  if (sameBytes(chipMapping, mappingPublic)) {
    throw const IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'The chip echoed the mapping key',
    );
  }
  final Agreement mapped;
  try {
    mapped = base.mapGeneric(nonce, mappingPrivate, chipMapping);
  } on FormatException catch (error) {
    throw IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'Invalid mapping key: ${error.message}',
    );
  }

  final (agreementPrivate, agreementPublic) = agreementKey == null
      ? mapped.generateKeyPair()
      : (agreementKey, mapped.publicKey(agreementKey));
  final chipAgreement = await _step(raw, tlv(0x83, agreementPublic), 0x84);
  if (sameBytes(chipAgreement, agreementPublic)) {
    throw const IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'The chip echoed the agreement key',
    );
  }
  final Uint8List secret;
  try {
    secret = mapped.sharedSecret(agreementPrivate, chipAgreement);
  } on FormatException catch (error) {
    throw IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'Invalid agreement key: ${error.message}',
    );
  }
  final encryptionKey = cipher.deriveKey(secret, 1);
  final macKey = cipher.deriveKey(secret, 2);

  final token = cipher.authenticationToken(
    macKey,
    mapped.publicKeyDataObject(oid, chipAgreement),
  );
  final answer = await raw.send(CommandApdu(
    0x00,
    0x86,
    0x00,
    0x00,
    data: tlv(0x7C, tlv(0x85, token)),
    le: 256,
  ));
  if (!answer.isSuccess) {
    // Wrong keys only show here, when the chip checks the token.
    throw IcaoAccessException(
      IcaoAccessFailure.wrongKey,
      'The chip refused the ${key is IcaoCanKey ? 'CAN' : 'MRZ'}',
      statusWord: answer.statusWord,
    );
  }
  final objects = _dynamicData(answer.data);
  final chipToken = objects[0x86];
  final expected = cipher.authenticationToken(
    macKey,
    mapped.publicKeyDataObject(oid, agreementPublic),
  );
  if (chipToken == null || !sameBytes(chipToken, expected)) {
    throw const IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'The chip authentication token does not hold',
    );
  }

  Uint8List? chipData;
  if (info.mapping == PaceMapping.chipAuthentication) {
    final encrypted = objects[0x8A];
    if (encrypted == null) {
      throw const IcaoAccessException(
        IcaoAccessFailure.protocolError,
        'Chip Authentication Mapping sent no authentication data',
      );
    }
    final iv = cipher.encryptBlock(
      encryptionKey,
      Uint8List(cipher.blockSize)..fillRange(0, cipher.blockSize, 0xFF),
    );
    try {
      chipData = unpad(cipher.decrypt(encryptionKey, encrypted, iv: iv));
    } on Object {
      throw const IcaoAccessException(
        IcaoAccessFailure.protocolError,
        'Undecipherable chip authentication data',
      );
    }
  }

  return PaceResult(
    SecureMessaging.fromZero(
      raw,
      cipher: cipher,
      encryptionKey: encryptionKey,
      macKey: macKey,
    ),
    info: info,
    chipMappingKey: chipMapping,
    chipAuthenticationData: chipData,
  );
}

// One chained GENERAL AUTHENTICATE: sends [content] in 7C, returns the
// value of [answerTag] from the 7C answer.
Future<Uint8List> _step(
  CardChannel raw,
  List<int> content,
  int answerTag,
) async {
  final response = await raw.send(CommandApdu(
    0x10,
    0x86,
    0x00,
    0x00,
    data: tlv(0x7C, content),
    le: 256,
  ));
  if (!response.isSuccess) {
    throw IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'GENERAL AUTHENTICATE failed',
      statusWord: response.statusWord,
    );
  }
  return _dynamicData(response.data)[answerTag] ??
      (throw const IcaoAccessException(
        IcaoAccessFailure.protocolError,
        'GENERAL AUTHENTICATE answered without the expected object',
      ));
}

Map<int, Uint8List> _dynamicData(Uint8List data) {
  try {
    final outer = Tlv.parse(data);
    if (outer.tag != 0x7C) throw const FormatException('No 7C');
    return {for (final object in outer.children) object.tag: object.value};
  } on FormatException {
    throw const IcaoAccessException(
      IcaoAccessFailure.protocolError,
      'Malformed GENERAL AUTHENTICATE answer',
    );
  }
}
