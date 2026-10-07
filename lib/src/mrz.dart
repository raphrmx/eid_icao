import 'package:eid/eid.dart';

/// The three layouts of a machine readable zone, ICAO 9303 parts 4 to 6.
enum IcaoMrzFormat {
  /// Three lines of 30 characters: identity cards.
  td1(3, 30),

  /// Two lines of 36 characters.
  td2(2, 36),

  /// Two lines of 44 characters: passports.
  td3(2, 44);

  const IcaoMrzFormat(this.lines, this.lineLength);

  /// The number of lines.
  final int lines;

  /// The characters per line.
  final int lineLength;
}

/// What kind of document an MRZ belongs to, from its first letter.
enum IcaoDocumentType {
  /// P: a passport.
  passport,

  /// I, A or C: an identity card or another official travel document, such
  /// as a residence permit.
  identityCard,

  /// V: a visa.
  visa,

  /// Any other letter.
  other,
}

/// The fields of the machine readable zone whose check digit did not match.
enum IcaoMrzField {
  /// The document number.
  documentNumber,

  /// The date of birth.
  birthDate,

  /// The date of expiry.
  expiryDate,

  /// The personal number of a passport.
  personalNumber,

  /// The composite check digit, over most of the zone.
  composite,
}

/// A machine readable zone, as printed on the document and stored in DG1.
///
/// ```dart
/// final mrz = IcaoMrz.parse(dg1Text);
/// mrz.lastName;     // SPECIMEN
/// mrz.birthDate;    // 1990-05-15
/// mrz.isValid;      // every check digit holds
/// ```
final class IcaoMrz {
  IcaoMrz._({
    required this.text,
    required this.format,
    required this.documentCode,
    required this.issuingState,
    required this.documentNumber,
    required this.lastName,
    required this.firstNames,
    required this.nationality,
    required this.birthDate,
    required this.sex,
    required this.expiryDate,
    required this.optionalData,
    required this.optionalData2,
    required this.invalidFields,
  });

  /// The same zone with its optional data replaced by fillers: the personal
  /// number of a passport, the optional fields of a card, where states such
  /// as Belgium put the national number.
  ///
  /// The document number stays whole, and [invalidFields] are those of the
  /// zone as read.
  IcaoMrz withoutOptionalData() {
    final lines = text.split('\n');
    String blank(String line, int start, int end) =>
        line.replaceRange(start, end, '<' * (end - start));
    // On a card, the part of a long document number that overflows into the
    // optional data, its check digit and a filler stay.
    final overflow =
        documentNumber.length > 9 ? documentNumber.length - 9 + 2 : 0;
    switch (format) {
      case IcaoMrzFormat.td1:
        lines[0] = blank(lines[0], 15 + overflow, 30);
        lines[1] = blank(lines[1], 18, 29);
      case IcaoMrzFormat.td2:
        lines[1] = blank(lines[1], 28 + overflow, 35);
      case IcaoMrzFormat.td3:
        lines[1] = blank(lines[1], 28, 43);
    }
    return IcaoMrz._(
      text: lines.join('\n'),
      format: format,
      documentCode: documentCode,
      issuingState: issuingState,
      documentNumber: documentNumber,
      lastName: lastName,
      firstNames: firstNames,
      nationality: nationality,
      birthDate: birthDate,
      sex: sex,
      expiryDate: expiryDate,
      optionalData: '',
      optionalData2: '',
      invalidFields: invalidFields,
    );
  }

  /// Reads an MRZ of any layout: its lines one per row, or run together.
  ///
  /// Lower case is tolerated. Lines separated by spaces or line breaks may
  /// have too few or too many fillers at their end, as when typed: they are
  /// fitted to the line length. Check digits are verified but do not stop
  /// the parse: see [invalidFields]. Throws a [FormatException] when the
  /// text is no MRZ.
  factory IcaoMrz.parse(String text) {
    final rows = text.toUpperCase().trim().split(RegExp(r'\s+'));
    final String clean;
    if (rows.length == 2 || rows.length == 3) {
      final width = rows.length == 3
          ? IcaoMrzFormat.td1.lineLength
          : rows.any((row) => row.length > 40)
              ? IcaoMrzFormat.td3.lineLength
              : IcaoMrzFormat.td2.lineLength;
      clean = rows.map((row) => _fitFillers(row, width)).join();
    } else {
      clean = rows.join();
    }
    final format = switch (clean.length) {
      90 => IcaoMrzFormat.td1,
      72 => IcaoMrzFormat.td2,
      88 => IcaoMrzFormat.td3,
      _ => throw FormatException('No MRZ has ${clean.length} characters'),
    };
    if (!RegExp(r'^[A-Z0-9<]+$').hasMatch(clean)) {
      throw const FormatException('An MRZ holds only A-Z, 0-9 and <');
    }
    final width = format.lineLength;
    final lines = [
      for (var i = 0; i < format.lines; i++)
        clean.substring(i * width, (i + 1) * width),
    ];
    return switch (format) {
      IcaoMrzFormat.td1 => _parseTd1(lines),
      IcaoMrzFormat.td2 => _parseTd2(lines),
      IcaoMrzFormat.td3 => _parseTd3(lines),
    };
  }

  /// The zone, one line per row.
  final String text;

  /// The layout.
  final IcaoMrzFormat format;

  /// The document code without fillers: `P`, `ID`, `IR`, `V`.
  final String documentCode;

  /// The issuing state or organisation, three letters or fewer: `BEL`, `D`.
  final String issuingState;

  /// The document number, the part that overflows into the optional data
  /// included.
  final String documentNumber;

  /// The primary identifier: the surname, its parts separated by spaces.
  final String lastName;

  /// The secondary identifier: the given names, separated by spaces. Empty
  /// when the holder has none.
  final String firstNames;

  /// The nationality, three letters or fewer.
  final String nationality;

  /// The date of birth, its unknown parts left out; null when unknown.
  final PartialDate? birthDate;

  /// The sex.
  final Sex sex;

  /// The date of expiry, or null when the document has none.
  final DateTime? expiryDate;

  /// The optional data without fillers: the personal number on a passport,
  /// the first optional field on a card.
  final String optionalData;

  /// The second optional field of a TD1 card, empty otherwise.
  final String optionalData2;

  /// The fields whose check digit does not match.
  final Set<IcaoMrzField> invalidFields;

  /// Whether every check digit holds.
  bool get isValid => invalidFields.isEmpty;

  /// What kind of document this is.
  IcaoDocumentType get documentType =>
      switch (documentCode.isEmpty ? '' : documentCode[0]) {
        'P' => IcaoDocumentType.passport,
        'I' || 'A' || 'C' => IcaoDocumentType.identityCard,
        'V' => IcaoDocumentType.visa,
        _ => IcaoDocumentType.other,
      };

  /// Whether the document expired before [date], today by default.
  bool isExpiredOn([DateTime? date]) {
    final expiry = expiryDate;
    if (expiry == null) return false;
    final day = date ?? DateTime.now();
    return DateTime.utc(day.year, day.month, day.day).isAfter(expiry);
  }

  @override
  String toString() => text;
}

IcaoMrz _parseTd1(List<String> lines) {
  final [line1, line2, line3] = lines;
  final invalid = <IcaoMrzField>{};
  final (number, optional) = _documentNumber(
    line1.substring(5, 14),
    line1[14],
    line1.substring(15, 30),
    invalid,
  );
  _checkField(line2.substring(0, 6), line2[6], IcaoMrzField.birthDate, invalid);
  _checkField(
      line2.substring(8, 14), line2[14], IcaoMrzField.expiryDate, invalid);
  _checkField(
    line1.substring(5, 30) +
        line2.substring(0, 7) +
        line2.substring(8, 15) +
        line2.substring(18, 29),
    line2[29],
    IcaoMrzField.composite,
    invalid,
  );
  final (last, first) = _names(line3);
  return IcaoMrz._(
    text: lines.join('\n'),
    format: IcaoMrzFormat.td1,
    documentCode: _code(line1.substring(0, 2)),
    issuingState: _code(line1.substring(2, 5)),
    documentNumber: number,
    lastName: last,
    firstNames: first,
    nationality: _code(line2.substring(15, 18)),
    birthDate: _birthDate(line2.substring(0, 6)),
    sex: _sex(line2[7]),
    expiryDate: _expiryDate(line2.substring(8, 14)),
    optionalData: optional,
    optionalData2: _filler(line2.substring(18, 29)),
    invalidFields: Set.unmodifiable(invalid),
  );
}

IcaoMrz _parseTd2(List<String> lines) {
  final [line1, line2] = lines;
  final invalid = <IcaoMrzField>{};
  final (number, optional) = _documentNumber(
    line2.substring(0, 9),
    line2[9],
    line2.substring(28, 35),
    invalid,
  );
  _checkField(
      line2.substring(13, 19), line2[19], IcaoMrzField.birthDate, invalid);
  _checkField(
      line2.substring(21, 27), line2[27], IcaoMrzField.expiryDate, invalid);
  _checkField(
    line2.substring(0, 10) + line2.substring(13, 20) + line2.substring(21, 35),
    line2[35],
    IcaoMrzField.composite,
    invalid,
  );
  final (last, first) = _names(line1.substring(5));
  return IcaoMrz._(
    text: lines.join('\n'),
    format: IcaoMrzFormat.td2,
    documentCode: _code(line1.substring(0, 2)),
    issuingState: _code(line1.substring(2, 5)),
    documentNumber: number,
    lastName: last,
    firstNames: first,
    nationality: _code(line2.substring(10, 13)),
    birthDate: _birthDate(line2.substring(13, 19)),
    sex: _sex(line2[20]),
    expiryDate: _expiryDate(line2.substring(21, 27)),
    optionalData: optional,
    optionalData2: '',
    invalidFields: Set.unmodifiable(invalid),
  );
}

IcaoMrz _parseTd3(List<String> lines) {
  final [line1, line2] = lines;
  final invalid = <IcaoMrzField>{};
  _checkField(
      line2.substring(0, 9), line2[9], IcaoMrzField.documentNumber, invalid);
  _checkField(
      line2.substring(13, 19), line2[19], IcaoMrzField.birthDate, invalid);
  _checkField(
      line2.substring(21, 27), line2[27], IcaoMrzField.expiryDate, invalid);
  // An empty personal number may carry < or 0 as its check digit.
  final personal = line2.substring(28, 42);
  if (!(personal == '<' * 14 && line2[42] == '<')) {
    _checkField(personal, line2[42], IcaoMrzField.personalNumber, invalid);
  }
  _checkField(
    line2.substring(0, 10) + line2.substring(13, 20) + line2.substring(21, 43),
    line2[43],
    IcaoMrzField.composite,
    invalid,
  );
  final (last, first) = _names(line1.substring(5));
  return IcaoMrz._(
    text: lines.join('\n'),
    format: IcaoMrzFormat.td3,
    documentCode: _code(line1.substring(0, 2)),
    issuingState: _code(line1.substring(2, 5)),
    documentNumber: _filler(line2.substring(0, 9)),
    lastName: last,
    firstNames: first,
    nationality: _code(line2.substring(10, 13)),
    birthDate: _birthDate(line2.substring(13, 19)),
    sex: _sex(line2[20]),
    expiryDate: _expiryDate(line2.substring(21, 27)),
    optionalData: _filler(personal),
    optionalData2: '',
    invalidFields: Set.unmodifiable(invalid),
  );
}

// [row] padded with fillers to [width], or cut to it when only fillers go.
String _fitFillers(String row, int width) {
  if (row.length < width) return row.padRight(width, '<');
  if (row.length > width && RegExp(r'^<+$').hasMatch(row.substring(width))) {
    return row.substring(0, width);
  }
  return row;
}

/// The ICAO 9303 check digit of [field]: weights 7, 3, 1, letters from 10,
/// the filler 0.
int mrzCheckDigit(String field) {
  const weights = [7, 3, 1];
  var sum = 0;
  for (var i = 0; i < field.length; i++) {
    final unit = field.codeUnitAt(i);
    final value = switch (unit) {
      >= 0x30 && <= 0x39 => unit - 0x30,
      >= 0x41 && <= 0x5A => unit - 0x41 + 10,
      _ => 0,
    };
    sum += value * weights[i % 3];
  }
  return sum % 10;
}

void _checkField(
  String field,
  String check,
  IcaoMrzField name,
  Set<IcaoMrzField> invalid,
) {
  final digit = check == '<' ? 0 : int.tryParse(check);
  if (digit != mrzCheckDigit(field)) invalid.add(name);
}

// A number over nine characters overflows into the optional data: its
// check digit field is <, and the optional data starts with the rest of the
// number and the check digit over the whole, then a filler.
(String, String) _documentNumber(
  String first,
  String check,
  String optional,
  Set<IcaoMrzField> invalid,
) {
  if (check == '<' && optional[0] != '<') {
    final end = optional.indexOf('<');
    final overflow = end < 0 ? optional : optional.substring(0, end);
    final number = first + overflow.substring(0, overflow.length - 1);
    _checkField(number, overflow[overflow.length - 1],
        IcaoMrzField.documentNumber, invalid);
    return (number, end < 0 ? '' : _filler(optional.substring(end)));
  }
  _checkField(first, check, IcaoMrzField.documentNumber, invalid);
  return (_filler(first), _filler(optional));
}

(String, String) _names(String field) {
  final trimmed = field.replaceFirst(RegExp(r'<+$'), '');
  final split = trimmed.indexOf('<<');
  final last = split < 0 ? trimmed : trimmed.substring(0, split);
  final first = split < 0 ? '' : trimmed.substring(split + 2);
  String spaced(String part) =>
      part.split('<').where((word) => word.isNotEmpty).join(' ');
  return (spaced(last), spaced(first));
}

String _code(String field) => field.replaceAll('<', '');

String _filler(String field) =>
    field.replaceAll(RegExp(r'^<+|<+$'), '').replaceAll('<', ' ');

Sex _sex(String char) => switch (char) {
      'M' => Sex.male,
      'F' => Sex.female,
      _ => Sex.unspecified,
    };

int? _twoDigits(String text) =>
    RegExp(r'^\d\d$').hasMatch(text) ? int.parse(text) : null;

// The birth year is the latest one not in the future.
PartialDate? _birthDate(String field) {
  final yy = _twoDigits(field.substring(0, 2));
  if (yy == null) return null;
  final now = DateTime.now().toUtc().year;
  final year = 2000 + yy > now ? 1900 + yy : 2000 + yy;
  final month = _twoDigits(field.substring(2, 4));
  final day = _twoDigits(field.substring(4, 6));
  if (month == null || month < 1 || month > 12) return PartialDate(year);
  final days = DateTime.utc(year, month + 1, 0).day;
  if (day == null || day < 1 || day > days) return PartialDate(year, month);
  return PartialDate(year, month, day);
}

// The expiry year is in this century, unless that puts it more than 50
// years ahead.
DateTime? _expiryDate(String field) {
  final yy = _twoDigits(field.substring(0, 2));
  final month = _twoDigits(field.substring(2, 4));
  final day = _twoDigits(field.substring(4, 6));
  if (yy == null || month == null || day == null) return null;
  if (month < 1 || month > 12 || day < 1 || day > 31) return null;
  final now = DateTime.now().toUtc().year;
  final year = 2000 + yy > now + 50 ? 1900 + yy : 2000 + yy;
  final date = DateTime.utc(year, month, day);
  return date.month == month ? date : null;
}

/// The MRZ field for [date]: YYMMDD, unknown parts as fillers.
String mrzDate(PartialDate date) {
  final year = (date.year % 100).toString().padLeft(2, '0');
  final month = date.month?.toString().padLeft(2, '0') ?? '<<';
  final day = date.day?.toString().padLeft(2, '0') ?? '<<';
  return '$year$month$day';
}
