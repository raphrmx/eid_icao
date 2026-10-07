import 'dart:convert';
import 'dart:typed_data';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/chip_authentication.dart';
import 'package:eid_icao/src/crypto/agreement.dart';
import 'package:eid_icao/src/crypto/named_parameters.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/image.dart';
import 'package:eid_icao/src/lds.dart';
import 'package:eid_icao/src/security_infos.dart';
import 'package:eid_icao/src/tlv.dart';
import 'package:test/test.dart';

import 'scripted_transport.dart';

Uint8List _text(int tag, String text) => tlv(tag, utf8.encode(text));

void main() {
  test('reads EF.COM', () {
    final com = IcaoCom.parse(tlv(
      0x60,
      concat([
        _text(0x5F01, '0107'),
        _text(0x5F36, '040000'),
        tlv(0x5C, const [0x61, 0x75, 0x6E, 0x99]),
      ]),
    ));
    expect(com.ldsVersion, '0107');
    expect(com.unicodeVersion, '040000');
    expect(com.dataGroups, [
      IcaoDataGroup.dg1,
      IcaoDataGroup.dg2,
      IcaoDataGroup.dg14,
    ]);
  });

  test('reads DG11, national characters and BCD dates included', () {
    final details = IcaoPersonalDetails.parse(tlv(
      0x6B,
      concat([
        tlv(0x5C, const [0x5F, 0x0E, 0x5F, 0x2B]),
        _text(0x5F0E, 'MÜLLER<GARCÍA<<JOSÉ<ÉLODIE'),
        tlv(0x5F2B, const [0x19, 0x85, 0x07, 0x00]),
        _text(0x5F10, '85073012345'),
        tlv(
            0xA0,
            concat([
              tlv(0x02, const [1]),
              _text(0x5F0F, 'JO<MULLER')
            ])),
        _text(0x5F42, 'RUE HAUTE 5<1000 BRUXELLES<BELGIQUE'),
        tlv(0x5F12, latin1.encode('+32 2 555 12 12')),
      ]),
    ));
    expect(details.lastName, 'MÜLLER GARCÍA');
    expect(details.firstNames, 'JOSÉ ÉLODIE');
    expect(details.birthDate, PartialDate(1985, 7));
    expect(details.personalNumber, '85073012345');
    expect(details.otherNames, ['JO MULLER']);
    expect(details.address, ['RUE HAUTE 5', '1000 BRUXELLES', 'BELGIQUE']);
    expect(details.telephone, '+32 2 555 12 12');
    expect(details.profession, isNull);
  });

  test('reads DG12 and DG16', () {
    final png = Uint8List.fromList([
      0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, //
      0, 0, 0, 13, 0x49, 0x48, 0x44, 0x52, 0, 0, 1, 0, 0, 0, 0, 0x80,
    ]);
    final details = IcaoDocumentDetails.parse(tlv(
      0x6C,
      concat([
        _text(0x5F19, 'COMMUNE DE NAMUR'),
        tlv(0x5F26, const [0x20, 0x24, 0x03, 0x14]),
        tlv(0x5F55, const [0x20, 0x24, 0x03, 0x07, 0x09, 0x30, 0x00]),
        tlv(0x5F1D, png),
      ]),
    ));
    expect(details.issuingAuthority, 'COMMUNE DE NAMUR');
    expect(details.issueDate, PartialDate(2024, 3, 14));
    expect(details.personalizationTime, DateTime.utc(2024, 3, 7, 9, 30));
    expect(details.frontImage?.format, IcaoImageFormat.png);
    expect(details.frontImage?.width, 256);
    expect(details.frontImage?.height, 128);

    final persons = parseDg16(tlv(
      0x70,
      concat([
        tlv(0x02, const [1]),
        tlv(
          0xA1,
          concat([
            _text(0x5F50, '20240101'),
            _text(0x5F51, 'SPECIMEN<<BOB'),
            _text(0x5F52, '+32 470 00 00 00'),
          ]),
        ),
      ]),
    ));
    expect(persons.single.name, 'SPECIMEN BOB');
    expect(persons.single.recordedOn, PartialDate(2024, 1, 1));
  });

  test('sizes a bare JPEG 2000 codestream', () {
    final codestream = Uint8List(40)
      ..setAll(0, const [0xFF, 0x4F, 0xFF, 0x51, 0, 41, 0, 0])
      ..setAll(8, const [0, 0, 1, 0x2C, 0, 0, 1, 0x86]);
    final image = IcaoImage.sniff(codestream);
    expect(image.format, IcaoImageFormat.jpeg2000);
    expect(image.width, 300);
    expect(image.height, 390);
    expect(image.mimeType, 'image/jp2');
  });

  test('refuses a file with the wrong tag', () {
    expect(() => parseDg1(tlv(0x75, const [])), throwsFormatException);
  });

  test('maps DH generic mapping the same way on both sides', () {
    final base = DhAgreement(modp2048Q224);
    final nonce = unsignedBigInt(randomBytes(16));
    final (terminalMap, terminalMapPublic) = base.generateKeyPair();
    final (chipMap, chipMapPublic) = base.generateKeyPair();
    final terminal = base.mapGeneric(nonce, terminalMap, chipMapPublic);
    final chip = base.mapGeneric(nonce, chipMap, terminalMapPublic);
    final (terminalKey, terminalPublic) = terminal.generateKeyPair();
    final (chipKey, chipPublic) = chip.generateKeyPair();
    expect(
      terminal.sharedSecret(terminalKey, chipPublic),
      chip.sharedSecret(chipKey, terminalPublic),
    );
    expect(
      () => terminal.sharedSecret(terminalKey, bigIntBytes(BigInt.one, 256)),
      throwsFormatException,
    );
  });

  test('runs Chip Authentication version 1 with MSE:Set KAT', () async {
    final chipKey = BigInt.from(123456789);
    final infos = SecurityInfos.parse(derSet([
      derSequence([
        derObjectIdentifier('0.4.0.127.0.7.2.2.3.2.1'),
        derInteger(BigInt.one),
      ]),
      derSequence([
        derObjectIdentifier('0.4.0.127.0.7.2.2.1.2'),
        derSequence([
          derSequence([
            derObjectIdentifier('1.2.840.10045.2.1'),
            derObjectIdentifier(secp256r1.objectIdentifier!),
          ]),
          derBitString(secp256r1.encode(secp256r1.multiplyGenerator(chipKey)!)),
        ]),
      ]),
    ]));
    final (info, key) = chipAuthenticationOf(infos)!;
    expect(key.publicKey, isA<EcPublicKey>());
    final transport = ScriptedTransport(['9000']);
    final channel = CardChannel(transport);
    final session = await performChipAuthentication(
      channel,
      channel,
      info,
      key,
      ephemeralKey: BigInt.from(42),
    );
    final public =
        secp256r1.encode(secp256r1.multiplyGenerator(BigInt.from(42))!);
    expect(
        transport.sent.single,
        '002241A643'
        '9141${hexString(public)}');
    expect(session.cipher.isAes, isFalse);
  });
}
