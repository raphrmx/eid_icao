import 'dart:typed_data';

import 'package:eid/eid.dart' show hexString;
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/certificate.dart';
import 'package:eid_icao/src/cms.dart';
import 'package:eid_icao/src/crypto/hash.dart';
import 'package:eid_icao/src/lds.dart';
import 'package:eid_icao/src/tlv.dart';

/// The content types an EF.SOD may declare: id-icao-ldsSecurityObject, and
/// two older identifiers some states still use, Belgium among them.
const ldsSecurityObjectTypes = {
  '2.23.136.1.1.1',
  '1.3.27.1.1.1',
  '1.2.528.1.1006.1.20.1',
};

/// How far up the document signer's certificate was traced.
enum IcaoChainStatus {
  /// A trusted CSCA issued it.
  verified,

  /// No CSCA was given: the signature holds, but nothing says the signer
  /// belongs to a state.
  unverified,

  /// CSCAs were given and none issued it.
  untrusted,
}

/// The outcome of Passive Authentication: the data groups match the hashes
/// in EF.SOD, which the document signer signed.
final class IcaoPassiveAuthentication {
  /// The checks of one document.
  const IcaoPassiveAuthentication({
    required this.signatureValid,
    required this.verifiedGroups,
    required this.mismatchedGroups,
    required this.chain,
    this.documentSigner,
    this.countrySigningCa,
    this.failure,
  });

  /// Whether the document signer's signature of EF.SOD holds.
  final bool signatureValid;

  /// The data groups whose hash matches EF.SOD.
  final Set<IcaoDataGroup> verifiedGroups;

  /// The data groups whose hash does not match, or that EF.SOD does not
  /// list.
  final Set<IcaoDataGroup> mismatchedGroups;

  /// Whether a trusted CSCA issued the document signer.
  final IcaoChainStatus chain;

  /// The document signer certificate (DSC), when found.
  final IcaoCertificate? documentSigner;

  /// The CSCA that issued it, when [chain] is verified.
  final IcaoCertificate? countrySigningCa;

  /// Why the check failed, when it did.
  final String? failure;

  /// Whether everything held: the signature, every hash, and the chain
  /// unless no CSCA was given.
  bool get isValid =>
      signatureValid &&
      mismatchedGroups.isEmpty &&
      chain != IcaoChainStatus.untrusted;

  @override
  String toString() =>
      'IcaoPassiveAuthentication(${isValid ? 'valid' : failure}'
      ', chain ${chain.name})';
}

/// Runs Passive Authentication, ICAO 9303 part 11, on files read from a
/// chip. It needs no chip: a server can run it on what a reader sent.
///
/// ```dart
/// final cscas = IcaoMasterList.parse(downloaded).cscas;
/// final result = IcaoPassiveAuthenticator(trustedRoots: cscas).verify(
///   sod: document.sod,
///   dataGroups: document.dataGroups,
/// );
/// ```
final class IcaoPassiveAuthenticator {
  /// An authenticator trusting the CSCAs [trustedRoots], or none.
  ///
  /// Without CSCAs, signatures and hashes are checked, and the chain is
  /// [IcaoChainStatus.unverified]. [documentSigners] adds DSCs for the
  /// documents whose EF.SOD leaves its signer out.
  IcaoPassiveAuthenticator({
    Iterable<IcaoCertificate>? trustedRoots,
    Iterable<IcaoCertificate> documentSigners = const [],
  })  : _roots = trustedRoots == null ? null : List.unmodifiable(trustedRoots),
        _signers = List.unmodifiable(documentSigners);

  final List<IcaoCertificate>? _roots;
  final List<IcaoCertificate> _signers;

  /// Checks [sod], EF.SOD as read, against [dataGroups], each data group
  /// as read.
  ///
  /// Never throws: a malformed file gives a result naming the [failure].
  IcaoPassiveAuthentication verify({
    required Uint8List sod,
    required Map<IcaoDataGroup, Uint8List> dataGroups,
  }) {
    final SignedData signed;
    final LdsSecurityObject security;
    try {
      final envelope = Tlv.parse(sod);
      signed = SignedData.parse(
        Uint8List.fromList(envelope.tag == 0x77 ? envelope.value : sod),
      );
      security = LdsSecurityObject.parse(signed.content);
    } on FormatException catch (error) {
      return _failed('EF.SOD is malformed: ${error.message}');
    }
    if (!ldsSecurityObjectTypes.contains(signed.contentType)) {
      return _failed('EF.SOD does not hold an LDS security object');
    }

    final verified = <IcaoDataGroup>{};
    final mismatched = <IcaoDataGroup>{};
    for (final MapEntry(key: group, value: file) in dataGroups.entries) {
      final expected = security.hashes[group.number];
      if (expected != null && sameBytes(security.hash.digest(file), expected)) {
        verified.add(group);
      } else {
        mismatched.add(group);
      }
    }

    final signer = _checkSigner(signed);
    return IcaoPassiveAuthentication(
      signatureValid: signer.$1,
      verifiedGroups: Set.unmodifiable(verified),
      mismatchedGroups: Set.unmodifiable(mismatched),
      chain: signer.$4,
      documentSigner: signer.$2,
      countrySigningCa: signer.$3,
      failure: signer.$5 ??
          (mismatched.isEmpty
              ? null
              : 'Hash mismatch: '
                  '${mismatched.map((group) => 'DG${group.number}').join(', ')}'),
    );
  }

  /// Checks a SignedData other than EF.SOD, such as EF.CardSecurity, and
  /// returns its content when the signature holds and the chain is not
  /// untrusted, or null.
  Uint8List? verifiedContent(Uint8List bytes, String contentType) {
    try {
      final signed = SignedData.parse(bytes);
      if (signed.contentType != contentType) return null;
      final (valid, _, _, chain, _) = _checkSigner(signed);
      return valid && chain != IcaoChainStatus.untrusted
          ? signed.content
          : null;
    } on FormatException {
      return null;
    }
  }

  (bool, IcaoCertificate?, IcaoCertificate?, IcaoChainStatus, String?)
      _checkSigner(SignedData signed) {
    final chainIfUnknown =
        _roots == null ? IcaoChainStatus.unverified : IcaoChainStatus.untrusted;
    if (signed.signers.isEmpty) {
      return (false, null, null, chainIfUnknown, 'EF.SOD has no signer');
    }
    final signer = signed.signers.first;
    final certificate = signed.certificateOf(signer, _signers);
    if (certificate == null) {
      return (
        false,
        null,
        null,
        chainIfUnknown,
        'The document signer certificate is missing',
      );
    }
    bool valid;
    try {
      valid = signer.verify(signed.contentType, signed.content, certificate);
    } on FormatException catch (error) {
      return (false, certificate, null, chainIfUnknown, error.message);
    }
    if (!valid) {
      return (
        false,
        certificate,
        null,
        chainIfUnknown,
        'The document signer signature does not hold',
      );
    }
    final roots = _roots;
    if (roots == null) {
      return (true, certificate, null, IcaoChainStatus.unverified, null);
    }
    final issuer = _issuerOf(certificate, roots);
    return issuer == null
        ? (
            true,
            certificate,
            null,
            IcaoChainStatus.untrusted,
            'No trusted CSCA issued the document signer',
          )
        : (true, certificate, issuer, IcaoChainStatus.verified, null);
  }

  // A DSC is shared by thousands of documents: once its issuer is found, it
  // is not looked for again by an authenticator with the same roots.
  final _issuers = <String, IcaoCertificate>{};

  IcaoCertificate? _issuerOf(
    IcaoCertificate certificate,
    List<IcaoCertificate> roots,
  ) {
    final key = hexString(HashAlgorithm.sha256.digest(certificate.der));
    final known = _issuers[key];
    if (known != null) return known;
    for (final root in roots) {
      if (!certificate.mayBeIssuedBy(root)) continue;
      try {
        if (certificate.isSignedBy(root)) {
          if (_issuers.length >= 256) _issuers.clear();
          return _issuers[key] = root;
        }
      } on FormatException {
        // A root with a key this package cannot use.
      }
    }
    return null;
  }

  IcaoPassiveAuthentication _failed(String failure) =>
      IcaoPassiveAuthentication(
        signatureValid: false,
        verifiedGroups: const {},
        mismatchedGroups: const {},
        chain: _roots == null
            ? IcaoChainStatus.unverified
            : IcaoChainStatus.untrusted,
        failure: failure,
      );
}
