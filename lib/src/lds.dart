import 'dart:convert';
import 'dart:typed_data';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/crypto/hash.dart';
import 'package:eid_icao/src/face_39794.dart';
import 'package:eid_icao/src/image.dart';
import 'package:eid_icao/src/mrz.dart';
import 'package:eid_icao/src/tlv.dart';

/// The data groups of the LDS, ICAO 9303 part 10.
enum IcaoDataGroup {
  /// DG1: the MRZ.
  dg1(1, 0x61),

  /// DG2: the face.
  dg2(2, 0x75),

  /// DG3: the fingerprints, behind Extended Access Control.
  dg3(3, 0x63),

  /// DG4: the irises, behind Extended Access Control.
  dg4(4, 0x76),

  /// DG5: the displayed portrait.
  dg5(5, 0x65),

  /// DG6: reserved.
  dg6(6, 0x66),

  /// DG7: the displayed signature or usual mark.
  dg7(7, 0x67),

  /// DG8: data features.
  dg8(8, 0x68),

  /// DG9: structure features.
  dg9(9, 0x69),

  /// DG10: substance features.
  dg10(10, 0x6A),

  /// DG11: additional personal details.
  dg11(11, 0x6B),

  /// DG12: additional document details.
  dg12(12, 0x6C),

  /// DG13: optional details, country specific.
  dg13(13, 0x6D),

  /// DG14: security options, for Chip Authentication.
  dg14(14, 0x6E),

  /// DG15: the Active Authentication public key.
  dg15(15, 0x6F),

  /// DG16: persons to notify.
  dg16(16, 0x70);

  const IcaoDataGroup(this.number, this.tag);

  /// The number, 1 to 16.
  final int number;

  /// The tag the file starts with.
  final int tag;

  /// The file identifier: 0101 to 0110.
  int get fileId => 0x0100 + number;

  /// The data group numbered [number], or null.
  static IcaoDataGroup? byNumber(int number) =>
      number >= 1 && number <= 16 ? values[number - 1] : null;

  /// The data group whose file starts with [tag], or null.
  static IcaoDataGroup? byTag(int tag) {
    for (final group in values) {
      if (group.tag == tag) return group;
    }
    return null;
  }
}

/// EF.COM: the LDS version and the data groups present. Not signed: trust
/// the list in EF.SOD instead.
final class IcaoCom {
  IcaoCom._(this.ldsVersion, this.unicodeVersion, this.dataGroups);

  /// Reads EF.COM. Throws a [FormatException] if malformed.
  factory IcaoCom.parse(Uint8List file) =>
      parseUntrusted(() => IcaoCom._parseUnchecked(file));

  factory IcaoCom._parseUnchecked(Uint8List file) {
    final com = _expectTag(file, 0x60, 'EF.COM');
    final tags = com.child(0x5C)?.value ?? Uint8List(0);
    return IcaoCom._(
      _ascii(com.child(0x5F01)?.value),
      _ascii(com.child(0x5F36)?.value),
      List.unmodifiable([
        for (final tag in tags)
          if (IcaoDataGroup.byTag(tag) case final group?) group,
      ]),
    );
  }

  /// The LDS version, such as `0107` for 1.7.
  final String? ldsVersion;

  /// The Unicode version, such as `040000`.
  final String? unicodeVersion;

  /// The data groups the chip lists.
  final List<IcaoDataGroup> dataGroups;
}

/// The LDSSecurityObject inside EF.SOD: a hash of each data group.
final class LdsSecurityObject {
  LdsSecurityObject._(this.hash, this.hashes, this.ldsVersion);

  /// Reads the DER content of the SOD's SignedData.
  factory LdsSecurityObject.parse(Uint8List content) =>
      parseUntrusted(() => LdsSecurityObject._parseUnchecked(content));

  factory LdsSecurityObject._parseUnchecked(Uint8List content) {
    final fields = Tlv.parse(content).children;
    if (fields.length < 3) throw const FormatException('Malformed SOD');
    final oid = fields[1].children.first.objectIdentifier;
    final hash = HashAlgorithm.fromObjectIdentifier(oid) ??
        (throw FormatException('Unsupported SOD hash $oid'));
    final hashes = <int, Uint8List>{};
    for (final entry in fields[2].children) {
      final parts = entry.children;
      hashes[parts[0].smallInteger] = Uint8List.fromList(parts[1].value);
    }
    String? version;
    if (fields.length > 3 && fields[3].tag == 0x30) {
      final info = fields[3].children;
      if (info.isNotEmpty) version = info.first.text;
    }
    return LdsSecurityObject._(hash, Map.unmodifiable(hashes), version);
  }

  /// The hash of the data groups.
  final HashAlgorithm hash;

  /// The hash of each data group, by number.
  final Map<int, Uint8List> hashes;

  /// The LDS version, from LDS 1.8 on.
  final String? ldsVersion;

  /// The data groups listed, in order.
  List<IcaoDataGroup> get dataGroups => [
        for (final number in hashes.keys.toList()..sort())
          if (IcaoDataGroup.byNumber(number) case final group?) group,
      ];
}

/// Reads DG1: the MRZ.
IcaoMrz parseDg1(Uint8List file) => parseUntrusted(() => _parseDg1(file));

IcaoMrz _parseDg1(Uint8List file) {
  final dg1 = _expectTag(file, 0x61, 'DG1');
  final mrz =
      dg1.child(0x5F1F) ?? (throw const FormatException('DG1 holds no MRZ'));
  return IcaoMrz.parse(ascii.decode(mrz.value, allowInvalid: true));
}

/// Where a face image came from.
enum IcaoFaceEncoding {
  /// ISO/IEC 19794-5:2005, the usual DG2 encoding.
  iso19794,

  /// ISO/IEC 39794-5, on documents issued from the late 2020s.
  iso39794,
}

/// A face read from DG2.
final class IcaoFace {
  /// [image], encoded in DG2 as [encoding].
  const IcaoFace(this.image, this.encoding);

  /// The image.
  final IcaoImage image;

  /// The biometric format it came in.
  final IcaoFaceEncoding encoding;
}

/// Reads the faces in DG2, ISO/IEC 19794-5 or 39794-5.
///
/// Throws a [FormatException] if malformed.
List<IcaoFace> parseDg2(Uint8List file) =>
    parseUntrusted(() => _parseDg2(file));

List<IcaoFace> _parseDg2(Uint8List file) =>
    _biometricBlocks(_expectTag(file, 0x75, 'DG2'))
        .expand(_facesOf)
        .toList(growable: false);

/// Reads the images of DG7, the displayed signature or usual mark.
List<IcaoImage> parseDg7(Uint8List file) =>
    parseUntrusted(() => _parseDg7(file));

List<IcaoImage> _parseDg7(Uint8List file) {
  final dg7 = _expectTag(file, 0x67, 'DG7');
  return [
    for (final element in dg7.children)
      if (element.tag == 0x5F43)
        IcaoImage.sniff(Uint8List.fromList(element.value)),
  ];
}

// The biometric data blocks of each template of a biometric information
// group template, 7F61.
Iterable<Tlv> _biometricBlocks(Tlv group) sync* {
  for (final template in group.children) {
    if (template.tag != 0x7F61) continue;
    for (final information in template.children) {
      if (information.tag != 0x7F60) continue;
      for (final element in information.children) {
        if (element.tag == 0x5F2E || element.tag == 0x7F2E) yield element;
      }
    }
  }
}

Iterable<IcaoFace> _facesOf(Tlv block) {
  final data = block.value;
  if (data.length > 4 &&
      data[0] == 0x46 &&
      data[1] == 0x41 &&
      data[2] == 0x43 &&
      data[3] == 0) {
    return _faces19794(data);
  }
  // ISO/IEC 39794-5: a FaceImageDataBlock, [APPLICATION 5], or its fields
  // straight under 7F2E.
  final List<Tlv> fields;
  if (data.isNotEmpty && data[0] == 0x65) {
    fields = Tlv.parse(data).children;
  } else {
    fields = Tlv.parseAll(data);
  }
  return [
    for (final image in faces39794(fields))
      IcaoFace(image, IcaoFaceEncoding.iso39794),
  ];
}

// ISO/IEC 19794-5:2005: a 14 byte header, then facial records.
List<IcaoFace> _faces19794(Uint8List data) {
  int u16(int i) => data[i] << 8 | data[i + 1];
  int u32(int i) =>
      data[i] << 24 | data[i + 1] << 16 | data[i + 2] << 8 | data[i + 3];
  if (data.length < 14) throw const FormatException('Truncated face header');
  final count = u16(12);
  final faces = <IcaoFace>[];
  var offset = 14;
  for (var n = 0; n < count; n++) {
    if (offset + 20 > data.length) {
      throw const FormatException('Truncated facial record');
    }
    final length = u32(offset);
    final points = u16(offset + 4);
    final info = offset + 20 + 8 * points;
    final image = info + 12;
    final end = offset + length;
    if (length < 32 || end > data.length || image > end) {
      throw const FormatException('Malformed facial record');
    }
    final bytes = Uint8List.fromList(data.sublist(image, end));
    faces.add(IcaoFace(
      sniffImage(
        bytes,
        format: data[info + 1] == 1
            ? IcaoImageFormat.jpeg2000
            : IcaoImageFormat.jpeg,
        width: u16(info + 2),
        height: u16(info + 4),
      ),
      IcaoFaceEncoding.iso19794,
    ));
    offset = end;
  }
  return faces;
}

/// DG11: additional personal details. Every field is optional.
final class IcaoPersonalDetails {
  IcaoPersonalDetails._({
    required this.lastName,
    required this.firstNames,
    required this.otherNames,
    required this.personalNumber,
    required this.birthDate,
    required this.birthPlace,
    required this.address,
    required this.telephone,
    required this.profession,
    required this.title,
    required this.personalSummary,
    required this.proofOfCitizenship,
    required this.otherTravelDocuments,
    required this.custodyInformation,
  });

  /// Reads DG11. Throws a [FormatException] if malformed.
  factory IcaoPersonalDetails.parse(Uint8List file) =>
      parseUntrusted(() => IcaoPersonalDetails._parseUnchecked(file));

  factory IcaoPersonalDetails._parseUnchecked(Uint8List file) {
    final dg11 = _expectTag(file, 0x6B, 'DG11');
    String? text(int tag) => _text(dg11.child(tag)?.value);
    final (last, first) = _splitName(text(0x5F0E));
    final others = <String>[
      for (final element in dg11.children)
        if (element.tag == 0x5F0F)
          _spaced(decodeText(element.value))
        else if (element.tag == 0xA0)
          for (final name in element.children)
            if (name.tag == 0x5F0F) _spaced(decodeText(name.value)),
    ];
    return IcaoPersonalDetails._(
      lastName: last,
      firstNames: first,
      otherNames: List.unmodifiable(others),
      personalNumber: text(0x5F10),
      birthDate: _date(dg11.child(0x5F2B)?.value),
      birthPlace: _parts(text(0x5F11)),
      address: _parts(text(0x5F42)),
      telephone: text(0x5F12),
      profession: text(0x5F13),
      title: text(0x5F14),
      personalSummary: text(0x5F15),
      proofOfCitizenship: switch (dg11.child(0x5F16)) {
        final image? => IcaoImage.sniff(Uint8List.fromList(image.value)),
        null => null,
      },
      otherTravelDocuments: List.unmodifiable(
        _parts(text(0x5F17)) ?? const <String>[],
      ),
      custodyInformation: text(0x5F18),
    );
  }

  /// The same details without [personalNumber].
  IcaoPersonalDetails withoutPersonalNumber() => IcaoPersonalDetails._(
        lastName: lastName,
        firstNames: firstNames,
        otherNames: otherNames,
        personalNumber: null,
        birthDate: birthDate,
        birthPlace: birthPlace,
        address: address,
        telephone: telephone,
        profession: profession,
        title: title,
        personalSummary: personalSummary,
        proofOfCitizenship: proofOfCitizenship,
        otherTravelDocuments: otherTravelDocuments,
        custodyInformation: custodyInformation,
      );

  /// The surname in full, national characters included.
  final String? lastName;

  /// The given names in full.
  final String? firstNames;

  /// Other names.
  final List<String> otherNames;

  /// The personal number.
  final String? personalNumber;

  /// The date of birth in full, unknown parts left out.
  final PartialDate? birthDate;

  /// The place of birth, its parts as written: town, then country.
  final List<String>? birthPlace;

  /// The permanent address, its parts as written: street, town, region,
  /// country.
  final List<String>? address;

  /// The telephone number.
  final String? telephone;

  /// The profession.
  final String? profession;

  /// The title.
  final String? title;

  /// A personal summary.
  final String? personalSummary;

  /// An image proving citizenship.
  final IcaoImage? proofOfCitizenship;

  /// Other valid travel document numbers.
  final List<String> otherTravelDocuments;

  /// Custody information.
  final String? custodyInformation;
}

/// DG12: additional document details. Every field is optional.
final class IcaoDocumentDetails {
  IcaoDocumentDetails._({
    required this.issuingAuthority,
    required this.issueDate,
    required this.otherPersons,
    required this.endorsements,
    required this.taxOrExitRequirements,
    required this.frontImage,
    required this.rearImage,
    required this.personalizationTime,
    required this.personalizationDevice,
  });

  /// Reads DG12. Throws a [FormatException] if malformed.
  factory IcaoDocumentDetails.parse(Uint8List file) =>
      parseUntrusted(() => IcaoDocumentDetails._parseUnchecked(file));

  factory IcaoDocumentDetails._parseUnchecked(Uint8List file) {
    final dg12 = _expectTag(file, 0x6C, 'DG12');
    String? text(int tag) => _text(dg12.child(tag)?.value);
    IcaoImage? image(int tag) => switch (dg12.child(tag)) {
          final element? => IcaoImage.sniff(Uint8List.fromList(element.value)),
          null => null,
        };
    final others = <String>[
      for (final element in dg12.children)
        if (element.tag == 0x5F1A)
          _spaced(decodeText(element.value))
        else if (element.tag == 0xA0)
          for (final name in element.children)
            if (name.tag == 0x5F1A) _spaced(decodeText(name.value)),
    ];
    return IcaoDocumentDetails._(
      issuingAuthority: text(0x5F19),
      issueDate: _date(dg12.child(0x5F26)?.value),
      otherPersons: List.unmodifiable(others),
      endorsements: text(0x5F1B),
      taxOrExitRequirements: text(0x5F1C),
      frontImage: image(0x5F1D),
      rearImage: image(0x5F1E),
      personalizationTime: _timestamp(dg12.child(0x5F55)?.value),
      personalizationDevice: text(0x5F56),
    );
  }

  /// The authority that issued the document.
  final String? issuingAuthority;

  /// The date of issue.
  final PartialDate? issueDate;

  /// Other persons included on the document.
  final List<String> otherPersons;

  /// Endorsements and observations.
  final String? endorsements;

  /// Tax or exit requirements.
  final String? taxOrExitRequirements;

  /// An image of the front of the document.
  final IcaoImage? frontImage;

  /// An image of the rear of the document.
  final IcaoImage? rearImage;

  /// When the chip was personalised.
  final DateTime? personalizationTime;

  /// The serial number of the personalisation system.
  final String? personalizationDevice;
}

/// A person to notify, from DG16.
final class IcaoPersonToNotify {
  const IcaoPersonToNotify._(
    this.recordedOn,
    this.name,
    this.telephone,
    this.address,
  );

  /// When the entry was recorded.
  final PartialDate? recordedOn;

  /// The name.
  final String? name;

  /// The telephone number.
  final String? telephone;

  /// The address, its parts as written.
  final List<String>? address;
}

/// Reads DG16. Throws a [FormatException] if malformed.
List<IcaoPersonToNotify> parseDg16(Uint8List file) =>
    parseUntrusted(() => _parseDg16(file));

List<IcaoPersonToNotify> _parseDg16(Uint8List file) {
  final dg16 = _expectTag(file, 0x70, 'DG16');
  return [
    for (final entry in dg16.children)
      if (entry.tag >= 0xA1 && entry.tag <= 0xA9)
        IcaoPersonToNotify._(
          _date(entry.child(0x5F50)?.value),
          switch (_text(entry.child(0x5F51)?.value)) {
            final name? => _spaced(name),
            null => null,
          },
          _text(entry.child(0x5F52)?.value),
          _parts(_text(entry.child(0x5F53)?.value)),
        ),
  ];
}

Tlv _expectTag(Uint8List file, int tag, String name) {
  final element = Tlv.parse(file);
  if (element.tag != tag) throw FormatException('Not $name');
  return element;
}

String? _ascii(List<int>? bytes) =>
    bytes == null ? null : ascii.decode(bytes, allowInvalid: true);

String? _text(List<int>? bytes) {
  if (bytes == null) return null;
  final text = decodeText(bytes).trim();
  return text.isEmpty ? null : text;
}

// Fillers become spaces: "VAN<DER<BERG" is "VAN DER BERG".
String _spaced(String text) =>
    text.split('<').where((part) => part.trim().isNotEmpty).join(' ').trim();

(String?, String?) _splitName(String? name) {
  if (name == null) return (null, null);
  final split = name.indexOf('<<');
  if (split < 0) return (_spaced(name), null);
  final first = _spaced(name.substring(split + 2));
  return (_spaced(name.substring(0, split)), first.isEmpty ? null : first);
}

List<String>? _parts(String? text) {
  if (text == null) return null;
  final parts = [
    for (final part in text.split('<'))
      if (part.trim().isNotEmpty) part.trim(),
  ];
  return parts.isEmpty ? null : List.unmodifiable(parts);
}

// YYYYMMDD in ASCII digits, or the same as 4 BCD bytes; unknown parts as
// zeros or fillers.
PartialDate? _date(List<int>? bytes) {
  if (bytes == null) return null;
  final text = bytes.length == 4
      ? bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join()
      : ascii.decode(bytes, allowInvalid: true);
  if (text.length != 8) return null;
  final year = int.tryParse(text.substring(0, 4));
  if (year == null || year == 0) return null;
  final month = int.tryParse(text.substring(4, 6));
  if (month == null || month < 1 || month > 12) return PartialDate(year);
  final day = int.tryParse(text.substring(6, 8));
  final days = DateTime.utc(year, month + 1, 0).day;
  if (day == null || day < 1 || day > days) return PartialDate(year, month);
  return PartialDate(year, month, day);
}

// YYYYMMDDHHMMSS, in ASCII digits or 7 BCD bytes.
DateTime? _timestamp(List<int>? bytes) {
  if (bytes == null) return null;
  final text = bytes.length == 7
      ? bytes.map((b) => b.toRadixString(16).padLeft(2, '0')).join()
      : ascii.decode(bytes, allowInvalid: true);
  final match =
      RegExp(r'^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)$').firstMatch(text);
  if (match == null) return null;
  final parts = [for (var i = 1; i <= 6; i++) int.parse(match[i]!)];
  return DateTime.utc(
      parts[0], parts[1], parts[2], parts[3], parts[4], parts[5]);
}
