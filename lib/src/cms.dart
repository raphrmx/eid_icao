import 'dart:typed_data';

import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/certificate.dart';
import 'package:eid_icao/src/crypto/hash.dart';
import 'package:eid_icao/src/crypto/signature.dart';
import 'package:eid_icao/src/tlv.dart';

/// A CMS SignedData, RFC 5652: the EF.SOD, EF.CardSecurity and master list
/// envelope.
final class SignedData {
  SignedData._(this.contentType, this.content, this.certificates, this.signers);

  /// Reads a ContentInfo holding a SignedData.
  ///
  /// Throws a [FormatException] when [bytes] hold anything else.
  factory SignedData.parse(Uint8List bytes) =>
      parseUntrusted(() => SignedData._parseUnchecked(bytes));

  factory SignedData._parseUnchecked(Uint8List bytes) {
    final info = Tlv.parse(bytes).children;
    if (info.length != 2 ||
        info[0].objectIdentifier != '1.2.840.113549.1.7.2') {
      throw const FormatException('Not a CMS SignedData');
    }
    final fields = info[1].children.first.children;
    if (fields.length < 4) throw const FormatException('Truncated SignedData');
    final encapsulated = fields[2].children;
    final contentType = encapsulated.first.objectIdentifier;
    final wrapped = encapsulated.length > 1
        ? encapsulated[1].children.first
        : throw const FormatException('Detached content');
    final certificates = <IcaoCertificate>[];
    var index = 3;
    if (fields[index].tag == 0xA0) {
      for (final certificate in fields[index].children) {
        if (certificate.tag != 0x30) continue;
        try {
          certificates.add(
            IcaoCertificate.parse(Uint8List.fromList(certificate.encoded)),
          );
        } on FormatException {
          // A certificate this package cannot read: the signer is looked
          // for among the others.
        }
      }
      index++;
    }
    if (index < fields.length && fields[index].tag == 0xA1) index++;
    if (index >= fields.length) throw const FormatException('No signer');
    return SignedData._(
      contentType,
      _octets(wrapped),
      List.unmodifiable(certificates),
      List.unmodifiable(fields[index].children.map(SignerInfo._parse)),
    );
  }

  /// The type of the signed content, such as id-icao-ldsSecurityObject.
  final String contentType;

  /// The signed content.
  final Uint8List content;

  /// The certificates the envelope carries, usually the signer's.
  final List<IcaoCertificate> certificates;

  /// The signers.
  final List<SignerInfo> signers;

  /// The certificate of [signer] among [certificates] and [others], or
  /// null.
  IcaoCertificate? certificateOf(
    SignerInfo signer, [
    Iterable<IcaoCertificate> others = const [],
  ]) {
    for (final certificate in [...certificates, ...others]) {
      if (signer.identifies(certificate)) return certificate;
    }
    return null;
  }
}

// An OCTET STRING, or the concatenated pieces of a constructed one.
Uint8List _octets(Tlv string) {
  if (string.tag == 0x04) return Uint8List.fromList(string.value);
  if (string.tag == 0x24) {
    return concat([for (final piece in string.children) _octets(piece)]);
  }
  throw const FormatException('Content is no OCTET STRING');
}

/// One signer of a [SignedData].
final class SignerInfo {
  SignerInfo._(
    this._issuer,
    this._serialNumber,
    this._keyIdentifier,
    this.digest,
    this._signedAttributes,
    this._signatureAlgorithm,
    this.signature,
  );

  factory SignerInfo._parse(Tlv info) {
    final fields = info.children;
    if (fields.length < 5) throw const FormatException('Truncated SignerInfo');
    final id = fields[1];
    final digestOid = fields[2].children.first.objectIdentifier;
    final digest = HashAlgorithm.fromObjectIdentifier(digestOid) ??
        (throw FormatException('Unsupported digest $digestOid'));
    var index = 3;
    Tlv? attributes;
    if (fields[index].tag == 0xA0) attributes = fields[index++];
    final identifier = id.children;
    return SignerInfo._(
      id.tag == 0x30 ? IcaoName.fromTlv(identifier[0]) : null,
      id.tag == 0x30 ? identifier[1].integer : null,
      id.tag == 0x80 ? Uint8List.fromList(id.value) : null,
      digest,
      attributes,
      Tlv.parse(Uint8List.fromList(fields[index].encoded)),
      Uint8List.fromList(fields[index + 1].value),
    );
  }

  final IcaoName? _issuer;
  final BigInt? _serialNumber;
  final Uint8List? _keyIdentifier;
  final Tlv? _signedAttributes;
  final Tlv _signatureAlgorithm;

  /// The hash of the signed content.
  final HashAlgorithm digest;

  /// The signature.
  final Uint8List signature;

  /// Whether [certificate] is the signer's.
  bool identifies(IcaoCertificate certificate) {
    final keyIdentifier = _keyIdentifier;
    if (keyIdentifier != null) {
      final subjectKey = certificate.subjectKeyIdentifier;
      return subjectKey != null && sameBytes(subjectKey, keyIdentifier);
    }
    return certificate.serialNumber == _serialNumber &&
        certificate.issuer.matches(_issuer!);
  }

  /// Whether [certificate]'s key signed [content] of type [contentType].
  ///
  /// With signed attributes, their content type and message digest must
  /// match too. Throws a [FormatException] when the algorithm or key is
  /// unsupported.
  bool verify(
    String contentType,
    Uint8List content,
    IcaoCertificate certificate,
  ) =>
      parseUntrusted(() => _verify(contentType, content, certificate));

  bool _verify(
    String contentType,
    Uint8List content,
    IcaoCertificate certificate,
  ) {
    final attributes = _signedAttributes;
    Uint8List signed;
    if (attributes == null) {
      signed = content;
    } else {
      final values = <String, Tlv>{};
      for (final attribute in attributes.children) {
        final parts = attribute.children;
        if (parts.length != 2) continue;
        final set = parts[1].children;
        if (set.isNotEmpty) values[parts[0].objectIdentifier] = set.first;
      }
      final type = values['1.2.840.113549.1.9.3'];
      final messageDigest = values['1.2.840.113549.1.9.4'];
      if (type == null ||
          messageDigest == null ||
          type.objectIdentifier != contentType ||
          !sameBytes(messageDigest.value, digest.digest(content))) {
        return false;
      }
      // The attributes are signed as a SET, not under their [0] tag.
      signed = Uint8List.fromList(attributes.encoded);
      signed[0] = 0x31;
    }
    return verifySignature(
      certificate.publicKey,
      _signatureAlgorithm,
      signed,
      signature,
      defaultHash: digest,
    );
  }
}
