import 'dart:convert';
import 'dart:typed_data';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/crypto/hash.dart';
import 'package:eid_icao/src/mrz.dart';

/// What opens the chip: the MRZ, for BAC or PACE, or the card access number
/// printed on the document, for PACE only.
///
/// Never logged: [toString] hides the values.
sealed class IcaoAccessKey {
  const IcaoAccessKey._();

  /// The key the MRZ gives: the document number, the dates of birth and
  /// expiry, as printed.
  ///
  /// A [birthDate] with unknown parts uses fillers, as the MRZ does. Throws
  /// an [ArgumentError] when [documentNumber] holds anything but letters,
  /// digits and fillers.
  factory IcaoAccessKey.mrz({
    required String documentNumber,
    required PartialDate birthDate,
    required DateTime expiryDate,
  }) = IcaoMrzKey;

  /// The key in a whole MRZ, two or three lines.
  ///
  /// Throws a [FormatException] when it is malformed, or when a check digit
  /// the key relies on does not match, which usually means a typo.
  factory IcaoAccessKey.fromMrz(String mrz) {
    final parsed = IcaoMrz.parse(mrz);
    const needed = {
      IcaoMrzField.documentNumber,
      IcaoMrzField.birthDate,
      IcaoMrzField.expiryDate,
    };
    final wrong = parsed.invalidFields.intersection(needed);
    if (wrong.isNotEmpty) {
      throw FormatException(
        'Check digit mismatch: ${wrong.map((field) => field.name).join(', ')}',
      );
    }
    final birthDate = parsed.birthDate;
    final expiryDate = parsed.expiryDate;
    if (birthDate == null || expiryDate == null) {
      throw const FormatException('The MRZ has no usable dates');
    }
    return IcaoMrzKey(
      documentNumber: parsed.documentNumber,
      birthDate: birthDate,
      expiryDate: expiryDate,
    );
  }

  /// The card access number printed on the document, usually six digits.
  ///
  /// Throws an [ArgumentError] unless [can] is digits only.
  factory IcaoAccessKey.can(String can) = IcaoCanKey;

  /// The secret PACE derives its password key from.
  Uint8List get paceSecret;

  /// The PACE password reference: 1 for the MRZ, 2 for the CAN.
  int get paceReference;
}

/// An [IcaoAccessKey] from the MRZ.
final class IcaoMrzKey extends IcaoAccessKey {
  /// See [IcaoAccessKey.mrz].
  IcaoMrzKey({
    required String documentNumber,
    required this.birthDate,
    required DateTime expiryDate,
  })  : documentNumber =
            documentNumber.toUpperCase().replaceAll(RegExp(r'\s'), ''),
        expiryDate =
            DateTime.utc(expiryDate.year, expiryDate.month, expiryDate.day),
        super._() {
    if (!RegExp(r'^[A-Z0-9<]+$').hasMatch(this.documentNumber)) {
      throw ArgumentError.value(
        '…',
        'documentNumber',
        'Letters, digits and < only',
      );
    }
  }

  /// The document number, upper case.
  final String documentNumber;

  /// The date of birth.
  final PartialDate birthDate;

  /// The date of expiry.
  final DateTime expiryDate;

  /// The MRZ information of ICAO 9303 part 11: document number, birth and
  /// expiry dates, each with its check digit.
  String get information {
    final number = documentNumber.length < 9
        ? documentNumber.padRight(9, '<')
        : documentNumber;
    final birth = mrzDate(birthDate);
    final expiry = mrzDate(
      PartialDate(expiryDate.year, expiryDate.month, expiryDate.day),
    );
    return '$number${mrzCheckDigit(number)}'
        '$birth${mrzCheckDigit(birth)}'
        '$expiry${mrzCheckDigit(expiry)}';
  }

  /// The BAC key seed: the first 16 bytes of the SHA-1 of [information].
  Uint8List get bacSeed => Uint8List.sublistView(paceSecret, 0, 16);

  @override
  Uint8List get paceSecret =>
      HashAlgorithm.sha1.digest(ascii.encode(information));

  @override
  int get paceReference => 1;

  @override
  String toString() => 'IcaoAccessKey.mrz(hidden)';
}

/// An [IcaoAccessKey] from the card access number.
final class IcaoCanKey extends IcaoAccessKey {
  /// See [IcaoAccessKey.can].
  IcaoCanKey(String can)
      : can = can.replaceAll(RegExp(r'\s'), ''),
        super._() {
    if (!RegExp(r'^\d+$').hasMatch(this.can)) {
      throw ArgumentError.value('…', 'can', 'Digits only');
    }
  }

  /// The card access number.
  final String can;

  @override
  Uint8List get paceSecret => Uint8List.fromList(ascii.encode(can));

  @override
  int get paceReference => 2;

  @override
  String toString() => 'IcaoAccessKey.can(hidden)';
}
