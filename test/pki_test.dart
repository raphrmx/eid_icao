import 'dart:typed_data';

import 'package:eid_icao/src/certificate.dart';
import 'package:eid_icao/src/cms.dart';
import 'package:eid_icao/src/crypto/named_parameters.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/tlv.dart';
import 'package:test/test.dart';

import 'openssl_pki.dart';

void main() {
  group('IcaoCertificate', () {
    test('reads a CSCA and a DSC with explicit brainpool parameters', () {
      final csca = IcaoCertificate.parse(cscaEc);
      final dsc = IcaoCertificate.parse(dscEc);
      expect(csca.subject.country, 'UT');
      expect(csca.subject.commonName, 'CSCA Utopia EC');
      expect(csca.isCa, isTrue);
      expect(dsc.isCa, isFalse);
      expect(dsc.issuer.matches(csca.subject), isTrue);
      expect(dsc.authorityKeyIdentifier, csca.subjectKeyIdentifier);
      expect((csca.publicKey as EcPublicKey).curve, brainpoolP384r1);
      expect((dsc.publicKey as EcPublicKey).curve, brainpoolP256r1);
      expect(dsc.notAfter.isAfter(dsc.notBefore), isTrue);
    });

    test('checks ECDSA signatures up the chain', () {
      final csca = IcaoCertificate.parse(cscaEc);
      final dsc = IcaoCertificate.parse(dscEc);
      expect(csca.isSignedBy(csca), isTrue);
      expect(dsc.mayBeIssuedBy(csca), isTrue);
      expect(dsc.isSignedBy(csca), isTrue);
      expect(dsc.isSignedBy(dsc), isFalse);
    });

    test('checks RSA-PSS signatures up the chain', () {
      final csca = IcaoCertificate.parse(cscaRsa);
      final dsc = IcaoCertificate.parse(dscRsa);
      expect(csca.isSignedBy(csca), isTrue);
      expect(dsc.isSignedBy(csca), isTrue);
      expect(dsc.isSignedBy(IcaoCertificate.parse(cscaEc)), isFalse);
    });

    test('refuses a tampered certificate', () {
      final tampered = Uint8List.fromList(dscEc);
      // A byte of the subject's common name.
      tampered[tampered.indexOf(0x45, 150)] ^= 0x20;
      final dsc = IcaoCertificate.parse(tampered);
      expect(dsc.isSignedBy(IcaoCertificate.parse(cscaEc)), isFalse);
    });
  });

  group('SignedData', () {
    for (final (name, sod) in [('ECDSA', sodEc), ('RSA-PSS', sodRsaPss)]) {
      test('verifies a $name EF.SOD', () {
        final data = SignedData.parse(Tlv.parse(sod).value);
        expect(data.contentType, '2.23.136.1.1.1');
        final signer = data.signers.single;
        final certificate = data.certificateOf(signer)!;
        expect(
            signer.verify(data.contentType, data.content, certificate), isTrue);

        final changed = Uint8List.fromList(data.content)..[10] ^= 1;
        expect(signer.verify(data.contentType, changed, certificate), isFalse);
        expect(
          signer.verify('2.23.136.1.1.2', data.content, certificate),
          isFalse,
        );
      });
    }

    test('reads a master list', () {
      final data = SignedData.parse(masterList);
      expect(data.contentType, '2.23.136.1.1.2');
      final list = Tlv.parse(data.content).children[1].children;
      expect(list, hasLength(2));
    });
  });
}
