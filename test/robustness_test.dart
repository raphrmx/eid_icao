import 'dart:math';
import 'dart:typed_data';

import 'package:eid_icao/eid_icao.dart';
import 'package:eid_icao/src/cms.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/lds.dart';
import 'package:eid_icao/src/security_infos.dart';
import 'package:eid_icao/src/tlv.dart';
import 'package:test/test.dart';

import 'openssl_pki.dart';

// Every parser must fail with a FormatException, nothing else.
void _onlyFormatErrors(void Function() parse) {
  try {
    parse();
  } on FormatException {
    // Expected for malformed input.
  }
}

void main() {
  final random = Random(1);
  final samples = <String, (Uint8List, void Function(Uint8List))>{
    'EF.SOD': (sodEc, (b) => SignedData.parse(Tlv.parse(b).value)),
    'certificate': (dscEc, IcaoCertificate.parse),
    'master list': (masterList, IcaoMasterList.parse),
    'DG1': (dg1, parseDg1),
    'key': (aaEcKey, PublicKey.parse),
  };

  for (final MapEntry(key: name, value: (sample, parse)) in samples.entries) {
    test('$name: truncated or corrupted input raises FormatException only', () {
      for (var length = 0; length < sample.length; length += 7) {
        _onlyFormatErrors(
            () => parse(Uint8List.sublistView(sample, 0, length)));
      }
      for (var i = 0; i < 300; i++) {
        final corrupted = Uint8List.fromList(sample);
        for (var j = 0; j < 3; j++) {
          corrupted[random.nextInt(corrupted.length)] = random.nextInt(256);
        }
        _onlyFormatErrors(() => parse(corrupted));
      }
    });
  }

  test('Passive Authentication never throws on a broken EF.SOD', () {
    final authenticator = IcaoPassiveAuthenticator(
      trustedRoots: [IcaoCertificate.parse(cscaEc)],
    );
    var invalid = 0;
    for (var i = 0; i < 200; i++) {
      final corrupted = Uint8List.fromList(sodEc);
      corrupted[random.nextInt(corrupted.length)] ^= 1 + random.nextInt(255);
      final result = authenticator.verify(
        sod: corrupted,
        dataGroups: {IcaoDataGroup.dg1: dg1},
      );
      if (!result.isValid) invalid++;
    }
    // A few bytes, such as version numbers, are outside the signatures.
    expect(invalid, greaterThan(180));
  });

  test('refuses explicit curve parameters that would hang or cost', () {
    // A composite p = 65, which used to send the square root search into
    // an endless loop.
    final parameters = derSequence([
      derInteger(BigInt.one),
      derSequence([
        derObjectIdentifier('1.2.840.10045.1.1'),
        derInteger(BigInt.from(65)),
      ]),
      derSequence([
        derOctetString(const [0]),
        derOctetString(const [1])
      ]),
      derOctetString(const [0x02, 0x00]),
      derInteger(BigInt.from(13)),
    ]);
    final cardAccess = derSet([
      derSequence([
        derObjectIdentifier('0.4.0.127.0.7.2.2.4.2'),
        derSequence([
          derObjectIdentifier('1.2.840.10045.2.1'),
          parameters,
        ]),
      ]),
    ]);
    expect(() => SecurityInfos.parse(cardAccess), throwsFormatException);
  });

  test('turns deep nesting into a FormatException', () {
    final deep = Uint8List(200000);
    for (var i = 0; i + 1 < deep.length; i += 2) {
      deep[i] = 0x30;
      deep[i + 1] = 0x80;
    }
    expect(() => SignedData.parse(deep), throwsFormatException);
  });

  test('reads an MRZ whose document code is fillers', () {
    final mrz = IcaoMrz.parse(
      '<<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n'
      'L898902C36UTO7408122F1204159ZE184226B<<<<<10',
    );
    expect(mrz.documentType, IcaoDocumentType.other);
  });
}
