import 'dart:typed_data';

import 'package:eid/eid.dart' show hexString;
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/crypto/signature.dart';
import 'package:eid_icao/src/tlv.dart';

/// A distinguished name, such as the subject of a certificate.
final class IcaoName {
  IcaoName._(this.encoded, this.attributes);

  /// Reads a DER Name.
  factory IcaoName.fromTlv(Tlv name) {
    final attributes = <(String, String)>[];
    for (final set in name.children) {
      for (final attribute in set.children) {
        final parts = attribute.children;
        if (parts.length != 2) continue;
        String value;
        try {
          value = parts[1].text;
        } on FormatException {
          value = hexString(parts[1].value);
        }
        attributes.add((parts[0].objectIdentifier, value));
      }
    }
    return IcaoName._(
        Uint8List.fromList(name.encoded), List.unmodifiable(attributes));
  }

  /// The name as encoded.
  final Uint8List encoded;

  /// Each attribute type, an OBJECT IDENTIFIER, with its value, in order.
  final List<(String, String)> attributes;

  /// The first value of the attribute [oid], or null.
  String? valueOf(String oid) {
    for (final (type, value) in attributes) {
      if (type == oid) return value;
    }
    return null;
  }

  /// The country, two letters: `BE`.
  String? get country => valueOf('2.5.4.6');

  /// The organisation.
  String? get organization => valueOf('2.5.4.10');

  /// The common name.
  String? get commonName => valueOf('2.5.4.3');

  /// Whether [other] names the same entity: the same encoding, or the same
  /// values compared without case and extra spaces.
  bool matches(IcaoName other) {
    if (sameBytes(encoded, other.encoded)) return true;
    if (attributes.length != other.attributes.length) return false;
    String normal(String value) =>
        value.trim().replaceAll(RegExp(r'\s+'), ' ').toLowerCase();
    for (var i = 0; i < attributes.length; i++) {
      final (type, value) = attributes[i];
      final (otherType, otherValue) = other.attributes[i];
      if (type != otherType || normal(value) != normal(otherValue)) {
        return false;
      }
    }
    return true;
  }

  @override
  String toString() => attributes
      .map((attribute) => '${_shortNames[attribute.$1] ?? attribute.$1}='
          '${attribute.$2}')
      .join(', ');

  static const _shortNames = {
    '2.5.4.3': 'CN',
    '2.5.4.5': 'serialNumber',
    '2.5.4.6': 'C',
    '2.5.4.7': 'L',
    '2.5.4.8': 'ST',
    '2.5.4.10': 'O',
    '2.5.4.11': 'OU',
  };
}

/// An X.509 certificate of the ICAO PKI: a country signing CA (CSCA), a
/// document signer (DSC), a master list signer.
final class IcaoCertificate {
  IcaoCertificate._({
    required this.der,
    required this.serialNumber,
    required this.issuer,
    required this.subject,
    required this.notBefore,
    required this.notAfter,
    required this.subjectKeyIdentifier,
    required this.authorityKeyIdentifier,
    required this.isCa,
    required this.subjectPublicKeyInfo,
    required Uint8List signed,
    required Tlv signatureAlgorithm,
    required Uint8List signature,
  })  : _signed = signed,
        _signatureAlgorithm = signatureAlgorithm,
        _signature = signature;

  /// Reads a DER certificate. Throws a [FormatException] if malformed.
  factory IcaoCertificate.parse(Uint8List der) =>
      parseUntrusted(() => IcaoCertificate._parseUnchecked(der));

  factory IcaoCertificate._parseUnchecked(Uint8List der) {
    final certificate = Tlv.parse(der);
    final parts = certificate.children;
    if (certificate.tag != 0x30 || parts.length != 3) {
      throw const FormatException('Not a certificate');
    }
    final tbs = parts[0].children;
    // The version, explicitly tagged [0], is absent from v1 certificates.
    final offset = tbs.isNotEmpty && tbs[0].tag == 0xA0 ? 1 : 0;
    if (tbs.length < offset + 6) {
      throw const FormatException('Truncated certificate');
    }
    final validity = tbs[offset + 3].children;
    if (validity.length != 2) throw const FormatException('Bad validity');

    Uint8List? subjectKeyId;
    Uint8List? authorityKeyId;
    var isCa = false;
    for (final field in tbs.skip(offset + 6)) {
      if (field.tag != 0xA3) continue;
      for (final extension in field.children.first.children) {
        final values = extension.children;
        final oid = values.first.objectIdentifier;
        final value = Tlv.parse(values.last.value);
        switch (oid) {
          case '2.5.29.14':
            subjectKeyId = Uint8List.fromList(value.value);
          case '2.5.29.35':
            final keyId = value.child(0x80);
            if (keyId != null) authorityKeyId = Uint8List.fromList(keyId.value);
          case '2.5.29.19':
            final constraints = value.children;
            isCa = constraints.isNotEmpty &&
                constraints.first.tag == 0x01 &&
                constraints.first.boolean;
        }
      }
    }
    final encoded = Uint8List.fromList(certificate.encoded);
    return IcaoCertificate._(
      der: encoded,
      serialNumber: tbs[offset].integer,
      issuer: IcaoName.fromTlv(tbs[offset + 2]),
      subject: IcaoName.fromTlv(tbs[offset + 4]),
      notBefore: validity[0].time,
      notAfter: validity[1].time,
      subjectKeyIdentifier: subjectKeyId,
      authorityKeyIdentifier: authorityKeyId,
      isCa: isCa,
      subjectPublicKeyInfo: Uint8List.fromList(tbs[offset + 5].encoded),
      signed: Uint8List.fromList(parts[0].encoded),
      signatureAlgorithm: Tlv.parse(Uint8List.fromList(parts[1].encoded)),
      signature: Uint8List.fromList(parts[2].bitString),
    );
  }

  /// The certificate as encoded.
  final Uint8List der;

  /// The serial number.
  final BigInt serialNumber;

  /// Who issued it.
  final IcaoName issuer;

  /// Whom it certifies.
  final IcaoName subject;

  /// The start of its validity.
  final DateTime notBefore;

  /// The end of its validity.
  final DateTime notAfter;

  /// Its subject key identifier, when it has one.
  final Uint8List? subjectKeyIdentifier;

  /// The key identifier of its issuer, when given.
  final Uint8List? authorityKeyIdentifier;

  /// Whether it is a CA certificate.
  final bool isCa;

  /// The public key, as a DER SubjectPublicKeyInfo.
  final Uint8List subjectPublicKeyInfo;

  final Uint8List _signed;
  final Tlv _signatureAlgorithm;
  final Uint8List _signature;

  /// Whether it was valid at [time].
  bool isValidAt(DateTime time) =>
      !time.isBefore(notBefore) && !time.isAfter(notAfter);

  /// Whether [issuer]'s key signed this certificate. The names are not
  /// compared here.
  ///
  /// Throws a [FormatException] when the algorithm or key is unsupported.
  bool isSignedBy(IcaoCertificate issuer) => verifySignature(
        issuer.publicKey,
        _signatureAlgorithm,
        _signed,
        _signature,
      );

  /// Whether [issuer] may have issued this certificate: its subject is this
  /// issuer, and the key identifiers agree when both are given.
  bool mayBeIssuedBy(IcaoCertificate issuer) {
    if (!this.issuer.matches(issuer.subject)) return false;
    final authority = authorityKeyIdentifier;
    final key = issuer.subjectKeyIdentifier;
    return authority == null || key == null || sameBytes(authority, key);
  }

  @override
  bool operator ==(Object other) =>
      other is IcaoCertificate && sameBytes(other.der, der);

  @override
  int get hashCode => Object.hashAll(der.take(64));

  @override
  String toString() => 'IcaoCertificate($subject)';
}

final _keys = Expando<PublicKey>();

/// The key of a certificate, parsed once.
extension IcaoCertificateKey on IcaoCertificate {
  /// The public key. Throws a [FormatException] for an unsupported one.
  PublicKey get publicKey =>
      _keys[this] ??= PublicKey.parse(subjectPublicKeyInfo);
}
