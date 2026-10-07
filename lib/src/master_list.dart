import 'dart:convert';
import 'dart:typed_data';

import 'package:eid_icao/src/certificate.dart';
import 'package:eid_icao/src/cms.dart';
import 'package:eid_icao/src/crypto/hash.dart';
import 'package:eid_icao/src/tlv.dart';

/// Certificates of the ICAO PKI, as they are published: a CSCA master list
/// (the `.ml` file in the German master list download), the LDIF files of
/// the ICAO PKD, or certificates in PEM or DER.
///
/// ```dart
/// final list = IcaoMasterList.parse(File('icaopkd-002.ldif').readAsBytesSync());
/// await IcaoReader(transport).read(access: key, trustedRoots: list.cscas);
/// ```
final class IcaoMasterList {
  IcaoMasterList._(this.certificates, this._lists)
      : cscas = List.unmodifiable(certificates.where((c) => c.isCa)),
        documentSigners = List.unmodifiable(certificates.where((c) => !c.isCa));

  /// Reads [bytes] in any of the supported forms. Certificates found twice
  /// are kept once; those this package cannot read are skipped.
  ///
  /// Throws a [FormatException] when nothing is recognised.
  factory IcaoMasterList.parse(Uint8List bytes) =>
      parseUntrusted(() => IcaoMasterList._parseUnchecked(bytes));

  factory IcaoMasterList._parseUnchecked(Uint8List bytes) {
    final found = <String, IcaoCertificate>{};
    final lists = <SignedData>[];

    void addCertificate(Uint8List der) {
      try {
        final certificate = IcaoCertificate.parse(der);
        found.putIfAbsent(
          base64Encode(HashAlgorithm.sha256.digest(certificate.der)),
          () => certificate,
        );
      } on FormatException {
        // Not a certificate this package reads.
      }
    }

    void addMasterList(Uint8List der) {
      final signed = SignedData.parse(der);
      if (signed.contentType != '2.23.136.1.1.2') {
        throw const FormatException('Not a CSCA master list');
      }
      lists.add(signed);
      final fields = Tlv.parse(signed.content).children;
      if (fields.length < 2) throw const FormatException('Empty master list');
      for (final certificate in fields[1].children) {
        addCertificate(Uint8List.fromList(certificate.encoded));
      }
    }

    void addDer(Uint8List der) {
      final first = Tlv.parse(der).children;
      if (first.isNotEmpty && first[0].tag == 0x06) {
        addMasterList(der);
      } else {
        addCertificate(der);
      }
    }

    final text = _asText(bytes);
    if (text == null) {
      addDer(bytes);
    } else if (text.contains('-----BEGIN CERTIFICATE-----')) {
      final pem = RegExp(
        '-----BEGIN CERTIFICATE-----([^-]+)-----END CERTIFICATE-----',
      );
      for (final match in pem.allMatches(text)) {
        addCertificate(base64Decode(match[1]!.replaceAll(RegExp(r'\s'), '')));
      }
    } else {
      for (final (name, value) in _ldifAttributes(text)) {
        final lower = name.toLowerCase();
        if (lower.startsWith('pkdmasterlistcontent')) {
          try {
            addMasterList(value);
          } on FormatException {
            // A list this package cannot read; the others still count.
          }
        } else if (lower.startsWith('usercertificate') ||
            lower.startsWith('cacertificate')) {
          addCertificate(value);
        }
      }
    }
    if (found.isEmpty) throw const FormatException('No certificate found');
    return IcaoMasterList._(List.unmodifiable(found.values), lists);
  }

  /// Every certificate found, each once.
  final List<IcaoCertificate> certificates;

  /// The CA certificates among them: the CSCAs and their link certificates,
  /// for `trustedRoots`.
  final List<IcaoCertificate> cscas;

  /// The others: document signers, as the ICAO PKD publishes them, for
  /// the documents whose EF.SOD leaves its signer out.
  final List<IcaoCertificate> documentSigners;

  final List<SignedData> _lists;

  /// The CSCAs of [country], two letters such as `BE`.
  List<IcaoCertificate> ofCountry(String country) => [
        for (final certificate in cscas)
          if (certificate.subject.country?.toUpperCase() ==
              country.toUpperCase())
            certificate,
      ];

  /// Whether every master list read is signed by a signer that a CSCA among
  /// [trusted], or among its own [cscas] when [trusted] is null, issued.
  ///
  /// A list vouching for itself proves only that it was not altered after
  /// signing; trust comes from where it was downloaded.
  bool verifySignatures([Iterable<IcaoCertificate>? trusted]) {
    if (_lists.isEmpty) return false;
    final roots = trusted?.toList() ?? cscas;
    for (final list in _lists) {
      var ok = false;
      for (final signer in list.signers) {
        final certificate = list.certificateOf(signer);
        if (certificate == null) continue;
        try {
          if (!signer.verify(list.contentType, list.content, certificate)) {
            continue;
          }
          ok = roots.any(
            (root) =>
                certificate.mayBeIssuedBy(root) && certificate.isSignedBy(root),
          );
        } on FormatException {
          continue;
        }
        if (ok) break;
      }
      if (!ok) return false;
    }
    return true;
  }
}

// The text in [bytes] when they are text, or null for binary.
String? _asText(Uint8List bytes) {
  if (bytes.isEmpty || bytes[0] == 0x30) return null;
  try {
    return utf8.decode(bytes);
  } on FormatException {
    return latin1.decode(bytes);
  }
}

// The base64 attributes (name:: value) of an LDIF file, continuation lines
// joined.
Iterable<(String, Uint8List)> _ldifAttributes(String text) sync* {
  final lines = const LineSplitter().convert(text);
  String? name;
  final value = StringBuffer();
  Iterable<(String, Uint8List)> flush() sync* {
    final current = name;
    if (current != null) {
      try {
        yield (current, base64Decode(value.toString()));
      } on FormatException {
        // A malformed value is skipped.
      }
    }
    name = null;
    value.clear();
  }

  for (final line in lines) {
    if (line.startsWith(' ')) {
      if (name != null) value.write(line.substring(1));
      continue;
    }
    yield* flush();
    final separator = line.indexOf(':: ');
    if (separator > 0) {
      name = line.substring(0, separator);
      value.write(line.substring(separator + 3).trim());
    }
  }
  yield* flush();
}
