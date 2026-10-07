import 'dart:convert';
import 'dart:typed_data';

import 'package:eid_icao/src/image.dart';
import 'package:eid_icao/src/lds.dart';
import 'package:eid_icao/src/mrz.dart';
import 'package:eid_icao/src/passive_authentication.dart';

/// What a read may bring back besides DG1, the MRZ, always read.
enum IcaoPart {
  /// DG2: the face, the largest file and most of the reading time.
  face,

  /// DG7: the displayed signature or usual mark.
  signature,

  /// DG11: full names, place of birth, address and other personal details.
  personalDetails,

  /// DG12: issuing authority, date of issue and other document details.
  documentDetails,

  /// DG16: persons to notify.
  personsToNotify;

  /// Every part.
  static const all = {
    face,
    signature,
    personalDetails,
    documentDetails,
    personsToNotify,
  };

  /// The data group the part lives in.
  IcaoDataGroup get dataGroup => switch (this) {
        face => IcaoDataGroup.dg2,
        signature => IcaoDataGroup.dg7,
        personalDetails => IcaoDataGroup.dg11,
        documentDetails => IcaoDataGroup.dg12,
        personsToNotify => IcaoDataGroup.dg16,
      };
}

/// How the chip was opened.
enum IcaoAccessProtocol {
  /// Basic Access Control, from the MRZ, on older documents.
  bac,

  /// PACE, from the MRZ or the CAN.
  pace,
}

/// How the chip proved it is the one issued, not a copy of its files.
enum IcaoChipAuthenticity {
  /// Chip Authentication: the chip holds the private key of DG14.
  chipAuthentication,

  /// PACE with Chip Authentication Mapping, which proves the same.
  chipAuthenticationMapping,

  /// Active Authentication: the chip signed a challenge with the private
  /// key of DG15.
  activeAuthentication,

  /// The chip offers no such proof, as on some older passports.
  notSupported,
}

/// Why a read turned a document down.
enum IcaoRejection {
  /// The document is expired.
  expired,

  /// The document type is not accepted.
  documentType,

  /// Passive Authentication failed: a data group was altered, the
  /// signature does not hold, or no trusted CSCA issued its signer.
  signature,

  /// The chip could not prove it is genuine.
  notGenuine,
}

/// A read turned the document down.
final class IcaoDocumentRejectedException implements Exception {
  /// The document whose MRZ is [mrz], turned down for [reason].
  const IcaoDocumentRejectedException(this.reason, this.mrz, {this.cause});

  /// Why it was turned down.
  final IcaoRejection reason;

  /// Its MRZ, from DG1.
  final IcaoMrz mrz;

  /// What failed, when known.
  final String? cause;

  @override
  String toString() => switch (reason) {
        IcaoRejection.expired => 'IcaoDocumentRejectedException: the '
            'document expired on '
            '${mrz.expiryDate?.toIso8601String().substring(0, 10)}',
        IcaoRejection.documentType => 'IcaoDocumentRejectedException: '
            'document type ${mrz.documentCode} is not accepted',
        IcaoRejection.signature =>
          'IcaoDocumentRejectedException: ${cause ?? 'bad signature'}',
        IcaoRejection.notGenuine => 'IcaoDocumentRejectedException: the chip '
            'could not prove it is genuine${cause == null ? '' : ' ($cause)'}',
      };
}

/// Everything an `IcaoReader.read` brings back from the chip.
///
/// The decoded fields come from [dataGroups], the files as read, which a
/// server can check again with an `IcaoPassiveAuthenticator`.
final class IcaoDocument {
  /// A document decoded from the files of its chip: EF.SOD and the data
  /// groups, DG1 included unless [mrz] stands in for it.
  ///
  /// Throws a [FormatException] when DG1 is malformed, or missing without
  /// [mrz]. Other data groups that fail to decode are named in
  /// [decodingFailures].
  factory IcaoDocument.fromFiles({
    required Uint8List sod,
    required Map<IcaoDataGroup, Uint8List> dataGroups,
    IcaoMrz? mrz,
    IcaoAccessProtocol? accessProtocol,
    Uint8List? cardSecurity,
    IcaoPassiveAuthentication? passiveAuthentication,
    IcaoChipAuthenticity? authenticity,
  }) {
    final dg1 = dataGroups[IcaoDataGroup.dg1];
    final zone = dg1 == null
        ? mrz ?? (throw const FormatException('DG1 is missing'))
        : parseDg1(dg1);
    final failures = <IcaoDataGroup, String>{};
    T? decode<T>(IcaoDataGroup group, T Function(Uint8List file) parse) {
      final file = dataGroups[group];
      if (file == null) return null;
      try {
        return parse(file);
      } on FormatException catch (error) {
        failures[group] = error.message;
        return null;
      }
    }

    return IcaoDocument._(
      mrz: zone,
      sod: sod,
      dataGroups: Map.unmodifiable(dataGroups),
      accessProtocol: accessProtocol,
      cardSecurity: cardSecurity,
      faces: List.unmodifiable(decode(IcaoDataGroup.dg2, parseDg2) ?? const []),
      signatureImages:
          List.unmodifiable(decode(IcaoDataGroup.dg7, parseDg7) ?? const []),
      personalDetails: decode(IcaoDataGroup.dg11, IcaoPersonalDetails.parse),
      documentDetails: decode(IcaoDataGroup.dg12, IcaoDocumentDetails.parse),
      personsToNotify:
          List.unmodifiable(decode(IcaoDataGroup.dg16, parseDg16) ?? const []),
      passiveAuthentication: passiveAuthentication,
      authenticity: authenticity,
      decodingFailures: Map.unmodifiable(failures),
    );
  }

  IcaoDocument._({
    required this.mrz,
    required this.sod,
    required this.dataGroups,
    required this.accessProtocol,
    required this.cardSecurity,
    required this.faces,
    required this.signatureImages,
    required this.personalDetails,
    required this.documentDetails,
    required this.personsToNotify,
    required this.passiveAuthentication,
    required this.authenticity,
    required this.decodingFailures,
  });

  /// The MRZ, from DG1.
  final IcaoMrz mrz;

  /// The faces in DG2, empty when it was not read.
  final List<IcaoFace> faces;

  /// The displayed signatures in DG7, empty when not read or absent.
  final List<IcaoImage> signatureImages;

  /// DG11, when read and present.
  final IcaoPersonalDetails? personalDetails;

  /// DG12, when read and present.
  final IcaoDocumentDetails? documentDetails;

  /// DG16, empty when not read or absent.
  final List<IcaoPersonToNotify> personsToNotify;

  /// EF.SOD as read.
  final Uint8List sod;

  /// Each data group as read.
  final Map<IcaoDataGroup, Uint8List> dataGroups;

  /// EF.CardSecurity, read for Chip Authentication Mapping.
  final Uint8List? cardSecurity;

  /// How the chip was opened, unknown for a document from JSON.
  final IcaoAccessProtocol? accessProtocol;

  /// The outcome of Passive Authentication, when it ran.
  final IcaoPassiveAuthentication? passiveAuthentication;

  /// What the chip proved about itself, when asked; never a failure, since
  /// such a read throws.
  final IcaoChipAuthenticity? authenticity;

  /// The data groups that could not be decoded, with the reason.
  final Map<IcaoDataGroup, String> decodingFailures;

  /// The same document without the personal numbers: the optional data of
  /// the MRZ become fillers, DG11 loses its personal number, and the raw
  /// DG1 and DG11, which hold them, are left out of [dataGroups].
  IcaoDocument withoutPrivateData() => IcaoDocument._(
        mrz: mrz.withoutOptionalData(),
        sod: sod,
        dataGroups: Map.unmodifiable({
          for (final MapEntry(:key, :value) in dataGroups.entries)
            if (key != IcaoDataGroup.dg1 && key != IcaoDataGroup.dg11)
              key: value,
        }),
        accessProtocol: accessProtocol,
        cardSecurity: cardSecurity,
        faces: faces,
        signatureImages: signatureImages,
        personalDetails: personalDetails?.withoutPersonalNumber(),
        documentDetails: documentDetails,
        personsToNotify: personsToNotify,
        passiveAuthentication: passiveAuthentication,
        authenticity: authenticity,
        decodingFailures: decodingFailures,
      );

  /// The first face, if any: the photo.
  IcaoImage? get face => faces.isEmpty ? null : faces.first.image;

  /// The photo as JPEG or PNG, ready for Flutter's `Image.memory`: the
  /// [face] as the chip holds it when JPEG, converted to PNG when JPEG 2000,
  /// as most identity cards store it. Null without a face, or if it cannot
  /// be decoded.
  Uint8List? get photo => face?.displayBytes;

  /// Whether Passive Authentication ran and held.
  bool get signaturesVerified => passiveAuthentication?.isValid ?? false;

  /// The files as JSON, bytes in base64, for [IcaoDocument.fromJson] and an
  /// `IcaoPassiveAuthenticator` on a server.
  ///
  /// Without DG1, as after [withoutPrivateData], the MRZ goes as text and a
  /// server cannot check it.
  Map<String, Object?> toJson() => {
        'sod': base64Encode(sod),
        if (!dataGroups.containsKey(IcaoDataGroup.dg1)) 'mrz': mrz.text,
        'dataGroups': {
          for (final MapEntry(:key, :value) in dataGroups.entries)
            '${key.number}': base64Encode(value),
        },
        if (cardSecurity case final bytes?) 'cardSecurity': base64Encode(bytes),
        if (accessProtocol case final protocol?)
          'accessProtocol': protocol.name,
        'signaturesVerified': signaturesVerified,
        if (authenticity case final authenticity?)
          'authenticity': authenticity.name,
      };

  /// What [toJson] wrote, decoded again.
  ///
  /// [passiveAuthentication] and [authenticity] are null: check again, with
  /// an `IcaoPassiveAuthenticator`. Throws a [FormatException] on malformed
  /// [json].
  factory IcaoDocument.fromJson(Map<String, Object?> json) {
    Uint8List bytes(Object? value, String key) => switch (value) {
          final String text => base64Decode(text),
          _ => throw FormatException('$key is not base64', value),
        };
    final groups = switch (json['dataGroups']) {
      final Map<String, Object?> map => map,
      final other => throw FormatException('dataGroups is no object', other),
    };
    return IcaoDocument.fromFiles(
      sod: bytes(json['sod'], 'sod'),
      mrz: switch (json['mrz']) {
        final String text => IcaoMrz.parse(text),
        _ => null,
      },
      dataGroups: {
        for (final MapEntry(:key, :value) in groups.entries)
          IcaoDataGroup.byNumber(int.tryParse(key) ?? 0) ??
                  (throw FormatException('Unknown data group', key)):
              bytes(value, 'DG$key'),
      },
      cardSecurity: json['cardSecurity'] == null
          ? null
          : bytes(json['cardSecurity'], 'cardSecurity'),
      accessProtocol: switch (json['accessProtocol']) {
        final String name =>
          IcaoAccessProtocol.values.where((p) => p.name == name).firstOrNull,
        _ => null,
      },
    );
  }
}
