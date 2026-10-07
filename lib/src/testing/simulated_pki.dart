import 'dart:typed_data';

import 'package:eid_icao/src/certificate.dart';
import 'package:eid_icao/src/crypto/hash.dart';
import 'package:eid_icao/src/crypto/named_parameters.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/crypto/signature.dart';
import 'package:eid_icao/src/tlv.dart';

/// The made-up PKI of the simulated documents: a CSCA of Utopia, the
/// fictional state of the ICAO specimens, and its document signer. The keys
/// are public, in this file: nothing it signs proves anything.
final class SimulatedPki {
  SimulatedPki._() {
    csca = _certificate(
      serial: 1,
      subject: _name('CSCA Utopia'),
      issuer: _name('CSCA Utopia'),
      key: _cscaKey,
      signer: _cscaKey,
      isCa: true,
    );
    documentSigner = _certificate(
      serial: 2,
      subject: _name('Document Signer Utopia'),
      issuer: _name('CSCA Utopia'),
      key: _dscKey,
      signer: _cscaKey,
      isCa: false,
    );
  }

  /// The one instance.
  static final instance = SimulatedPki._();

  static final _cscaKey = BigInt.parse(
    '91abdf10393277cb96a4622a5fcf9a284147c248ef6f2cb489be541e7f355d98',
    radix: 16,
  );
  static final _dscKey = BigInt.parse(
    '2caaf46b478d7b64d90a82fca3322e5726e03447308250e635273e21884a2802',
    radix: 16,
  );

  /// The CSCA, self-signed.
  late final IcaoCertificate csca;

  /// The document signer, issued by [csca].
  late final IcaoCertificate documentSigner;

  /// A CMS SignedData of [content], typed [contentType], signed by the
  /// document signer.
  Uint8List signedData(String contentType, Uint8List content) {
    final attributes = derSet([
      derSequence([
        derObjectIdentifier('1.2.840.113549.1.9.3'),
        derSet([derObjectIdentifier(contentType)]),
      ]),
      derSequence([
        derObjectIdentifier('1.2.840.113549.1.9.4'),
        derSet([derOctetString(HashAlgorithm.sha256.digest(content))]),
      ]),
    ]);
    final signature = _sign(_dscKey, attributes);
    // The attributes are signed as a SET and stored under [0].
    final storedAttributes = Uint8List.fromList(attributes)..[0] = 0xA0;
    final sha256 = derSequence([
      derObjectIdentifier(HashAlgorithm.sha256.objectIdentifier),
    ]);
    final signer = derSequence([
      derInteger(BigInt.one),
      derSequence([
        _name('CSCA Utopia'),
        derInteger(BigInt.two),
      ]),
      sha256,
      storedAttributes,
      derSequence([derObjectIdentifier('1.2.840.10045.4.3.2')]),
      derOctetString(signature),
    ]);
    final signedData = derSequence([
      derInteger(BigInt.from(3)),
      derSet([sha256]),
      derSequence([
        derObjectIdentifier(contentType),
        tlv(0xA0, derOctetString(content)),
      ]),
      tlv(0xA0, documentSigner.der),
      derSet([signer]),
    ]);
    return derSequence([
      derObjectIdentifier('1.2.840.113549.1.7.2'),
      tlv(0xA0, signedData),
    ]);
  }

  static EcPublicKey publicKeyOf(BigInt key) => EcPublicKey(
        brainpoolP256r1,
        brainpoolP256r1.multiplyGenerator(key)!,
      );

  static Uint8List subjectPublicKeyInfo(EcPublicKey key) => derSequence([
        derSequence([
          derObjectIdentifier('1.2.840.10045.2.1'),
          derObjectIdentifier(key.curve.objectIdentifier!),
        ]),
        derBitString(key.curve.encode(key.point)),
      ]);

  // An ECDSA signature with SHA-256, DER.
  static Uint8List _sign(BigInt key, List<int> data) {
    final (r, s) = signEcdsa(
      publicKeyOf(key),
      key,
      HashAlgorithm.sha256.digest(data),
    );
    return derSequence([derInteger(r), derInteger(s)]);
  }

  static Uint8List _name(String commonName) => derSequence([
        derSet([
          derSequence(
              [derObjectIdentifier('2.5.4.6'), derPrintableString('UT')]),
        ]),
        derSet([
          derSequence(
              [derObjectIdentifier('2.5.4.10'), derUtf8String('Utopia')]),
        ]),
        derSet([
          derSequence(
              [derObjectIdentifier('2.5.4.3'), derUtf8String(commonName)]),
        ]),
      ]);

  static IcaoCertificate _certificate({
    required int serial,
    required Uint8List subject,
    required Uint8List issuer,
    required BigInt key,
    required BigInt signer,
    required bool isCa,
  }) {
    final publicKey = subjectPublicKeyInfo(publicKeyOf(key));
    final keyId = HashAlgorithm.sha1.digest(publicKey);
    final issuerKeyId = HashAlgorithm.sha1.digest(
      subjectPublicKeyInfo(publicKeyOf(signer)),
    );
    Uint8List extension(String oid, Uint8List value, {bool critical = false}) =>
        derSequence([
          derObjectIdentifier(oid),
          if (critical) tlv(0x01, const [0xFF]),
          derOctetString(value),
        ]);
    final algorithm = derSequence([derObjectIdentifier('1.2.840.10045.4.3.2')]);
    final tbs = derSequence([
      tlv(0xA0, derInteger(BigInt.two)),
      derInteger(BigInt.from(serial)),
      algorithm,
      issuer,
      derSequence([
        derTime(DateTime.utc(2024)),
        derTime(DateTime.utc(isCa ? 2044 : 2036)),
      ]),
      subject,
      publicKey,
      tlv(
        0xA3,
        derSequence([
          extension('2.5.29.14', derOctetString(keyId)),
          if (!isCa)
            extension('2.5.29.35', derSequence([tlv(0x80, issuerKeyId)])),
          if (isCa)
            extension(
              '2.5.29.19',
              derSequence([
                tlv(0x01, const [0xFF])
              ]),
              critical: true,
            ),
          extension(
            '2.5.29.15',
            derBitString([if (isCa) 0x06 else 0x80]),
            critical: true,
          ),
        ]),
      ),
    ]);
    return IcaoCertificate.parse(derSequence([
      tbs,
      algorithm,
      derBitString(_sign(signer, tbs)),
    ]));
  }
}

/// The SubjectPublicKeyInfo of a simulated RSA key.
Uint8List rsaSubjectPublicKeyInfo(RsaPublicKey key) => derSequence([
      derSequence([derObjectIdentifier('1.2.840.113549.1.1.1'), derNull]),
      derBitString(derSequence([
        derInteger(key.modulus),
        derInteger(key.exponent),
      ])),
    ]);
