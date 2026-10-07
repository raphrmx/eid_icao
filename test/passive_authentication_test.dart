import 'dart:convert';
import 'dart:typed_data';

import 'package:eid_icao/src/certificate.dart';
import 'package:eid_icao/src/chip_authentication.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/lds.dart';
import 'package:eid_icao/src/master_list.dart';
import 'package:eid_icao/src/passive_authentication.dart';
import 'package:test/test.dart';

import 'openssl_pki.dart';

void main() {
  final groups = {IcaoDataGroup.dg1: dg1, IcaoDataGroup.dg2: dg2};
  final cscas = [
    IcaoCertificate.parse(cscaEc),
    IcaoCertificate.parse(cscaRsa),
  ];

  group('IcaoPassiveAuthenticator', () {
    for (final (name, sod) in [
      ('ECDSA', sodEc),
      ('RSA-PSS', sodRsaPss),
      ('older content type', sodOldType),
    ]) {
      test('verifies a $name document up to its CSCA', () {
        final result = IcaoPassiveAuthenticator(trustedRoots: cscas)
            .verify(sod: sod, dataGroups: groups);
        expect(result.isValid, isTrue, reason: result.failure);
        expect(result.chain, IcaoChainStatus.verified);
        expect(result.verifiedGroups, groups.keys.toSet());
        expect(result.countrySigningCa?.subject.country, 'UT');
        expect(parseDg1(dg1).lastName, 'ERIKSSON');
      });
    }

    test('leaves the chain unverified without CSCAs', () {
      final result =
          IcaoPassiveAuthenticator().verify(sod: sodEc, dataGroups: groups);
      expect(result.isValid, isTrue);
      expect(result.chain, IcaoChainStatus.unverified);
    });

    test('distrusts a signer no given CSCA issued', () {
      final result = IcaoPassiveAuthenticator(trustedRoots: [cscas[1]])
          .verify(sod: sodEc, dataGroups: groups);
      expect(result.signatureValid, isTrue);
      expect(result.chain, IcaoChainStatus.untrusted);
      expect(result.isValid, isFalse);
    });

    test('names a data group that was changed', () {
      final changed = Uint8List.fromList(dg2)..[3] ^= 1;
      final result = IcaoPassiveAuthenticator(trustedRoots: cscas).verify(
        sod: sodEc,
        dataGroups: {IcaoDataGroup.dg1: dg1, IcaoDataGroup.dg2: changed},
      );
      expect(result.mismatchedGroups, {IcaoDataGroup.dg2});
      expect(result.isValid, isFalse);
      expect(result.failure, contains('DG2'));
    });

    test('reports a malformed EF.SOD without throwing', () {
      final result = IcaoPassiveAuthenticator().verify(
          sod: Uint8List.fromList([0x77, 0x02, 0x30, 0x00]),
          dataGroups: groups);
      expect(result.isValid, isFalse);
      expect(result.failure, contains('malformed'));
    });
  });

  group('IcaoMasterList', () {
    test('reads a CMS master list and checks its signature', () {
      final list = IcaoMasterList.parse(masterList);
      expect(list.certificates, hasLength(2));
      expect(list.cscas, hasLength(2));
      expect(list.documentSigners, isEmpty);
      expect(list.ofCountry('ut'), hasLength(2));
      expect(list.verifySignatures(), isTrue);
    });

    test('reads PEM certificates', () {
      String pem(Uint8List der) => '-----BEGIN CERTIFICATE-----\n'
          '${base64Encode(der)}\n-----END CERTIFICATE-----\n';
      final list = IcaoMasterList.parse(
        Uint8List.fromList(utf8.encode(pem(cscaEc) + pem(dscRsa))),
      );
      expect(list.cscas.single.subject.commonName, 'CSCA Utopia EC');
      expect(list.documentSigners.single.subject.commonName,
          'Document Signer RSA');
    });

    test('reads master lists out of an ICAO PKD LDIF file', () {
      final encoded = base64Encode(masterList);
      final folded = [
        for (var i = 0; i < encoded.length; i += 76)
          encoded.substring(
              i, i + 76 > encoded.length ? encoded.length : i + 76),
      ];
      final ldif = 'dn: cn=UT,dc=CSCAMasterList,dc=pkdDownload\n'
          'objectClass: CscaMasterList\n'
          'pkdMasterListContent:: ${folded.join('\n ')}\n\n';
      final list = IcaoMasterList.parse(Uint8List.fromList(utf8.encode(ldif)));
      expect(list.certificates, hasLength(2));
    });
  });

  group('Active Authentication', () {
    test('checks an RSA answer, ISO 9796-2', () {
      final key = PublicKey.parse(aaRsaKey);
      expect(
          verifyActiveAuthentication(key, aaChallenge, aaRsaSignature), isTrue);
      expect(
        verifyActiveAuthentication(key, Uint8List(8), aaRsaSignature),
        isFalse,
      );
    });

    test('checks a plain ECDSA answer', () {
      final key = PublicKey.parse(aaEcKey);
      expect(
        verifyActiveAuthentication(
          key,
          aaChallenge,
          aaEcSignature,
          ecdsaAlgorithm: '0.4.0.127.0.7.1.1.4.1.3',
        ),
        isTrue,
      );
      final forged = Uint8List.fromList(aaEcSignature)..[5] ^= 1;
      expect(verifyActiveAuthentication(key, aaChallenge, forged), isFalse);
    });
  });
}
