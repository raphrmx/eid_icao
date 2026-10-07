import 'package:eid/eid.dart';
import 'package:eid_icao/src/access_key.dart';
import 'package:eid_icao/src/mrz.dart';
import 'package:test/test.dart';

// The specimens of ICAO 9303 parts 4, 5 and 6.
const _td3 = 'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n'
    'L898902C36UTO7408122F1204159ZE184226B<<<<<10';
const _td1 = 'I<UTOD231458907<<<<<<<<<<<<<<<\n'
    '7408122F1204159UTO<<<<<<<<<<<6\n'
    'ERIKSSON<<ANNA<MARIA<<<<<<<<<<';
const _td2 = 'I<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<\n'
    'D231458907UTO7408122F1204159<<<<<<<6';

void main() {
  test('reads a passport MRZ', () {
    final mrz = IcaoMrz.parse(_td3);
    expect(mrz.format, IcaoMrzFormat.td3);
    expect(mrz.documentType, IcaoDocumentType.passport);
    expect(mrz.documentCode, 'P');
    expect(mrz.issuingState, 'UTO');
    expect(mrz.lastName, 'ERIKSSON');
    expect(mrz.firstNames, 'ANNA MARIA');
    expect(mrz.documentNumber, 'L898902C3');
    expect(mrz.nationality, 'UTO');
    expect(mrz.birthDate, PartialDate(1974, 8, 12));
    expect(mrz.sex, Sex.female);
    expect(mrz.expiryDate, DateTime.utc(2012, 4, 15));
    expect(mrz.optionalData, 'ZE184226B');
    expect(mrz.isValid, isTrue);
    expect(mrz.isExpiredOn(DateTime.utc(2026)), isTrue);
  });

  test('reads a card MRZ, lines run together', () {
    final mrz = IcaoMrz.parse(_td1.replaceAll('\n', ''));
    expect(mrz.format, IcaoMrzFormat.td1);
    expect(mrz.documentType, IcaoDocumentType.identityCard);
    expect(mrz.documentNumber, 'D23145890');
    expect(mrz.lastName, 'ERIKSSON');
    expect(mrz.isValid, isTrue);
    expect(mrz.text, _td1);
  });

  test('reads a TD2 MRZ', () {
    final mrz = IcaoMrz.parse(_td2);
    expect(mrz.format, IcaoMrzFormat.td2);
    expect(mrz.documentNumber, 'D23145890');
    expect(mrz.firstNames, 'ANNA MARIA');
    expect(mrz.isValid, isTrue);
  });

  test('joins a document number that overflows into the optional data', () {
    // A Belgian card number of 12 digits, its check digit at the end.
    const mrz = 'IDBEL592123456<7891<<<<<<<<<<<\n'
        '9005157F3403133BEL<<<<<<<<<<<0\n'
        'SPECIMEN<<ALICE<MARIE<<<<<<<<<';
    final parsed = IcaoMrz.parse(mrz);
    expect(mrz.split('\n').map((line) => line.length), [30, 30, 30]);
    expect(parsed.documentNumber, '592123456789');
    expect(parsed.invalidFields, isNot(contains(IcaoMrzField.documentNumber)));
    expect(parsed.optionalData, '');
  });

  test('names the fields whose check digit fails', () {
    final typo = _td3.replaceFirst('7408122', '7408132');
    expect(
      IcaoMrz.parse(typo).invalidFields,
      {IcaoMrzField.birthDate, IcaoMrzField.composite},
    );
    expect(() => IcaoAccessKey.fromMrz(typo), throwsFormatException);
  });

  test('keeps unknown parts of a birth date out', () {
    final mrz = IcaoMrz.parse(
      _td3.replaceFirst('7408122', '74<<<<0'),
    );
    expect(mrz.birthDate, PartialDate(1974));
  });

  test('fits the fillers at the end of typed lines', () {
    final typed = _td1
        .split('\n')
        .map((line) => line.replaceFirst(RegExp(r'<+$'), '<<<'))
        .join(' ');
    final mrz = IcaoMrz.parse('$typed<<<<<<<<<<<<<<<<<<<<<<<<<<<<<');
    expect(mrz.text, _td1);
    expect(mrz.isValid, isTrue);
  });

  test('refuses what is no MRZ', () {
    expect(() => IcaoMrz.parse('P<UTO'), throwsFormatException);
    expect(
      () => IcaoMrz.parse(_td3.replaceFirst('P<', 'P?')),
      throwsFormatException,
    );
  });

  group('IcaoAccessKey', () {
    test('builds the MRZ information of the BAC example', () {
      final key = IcaoAccessKey.mrz(
        documentNumber: 'L898902C<',
        birthDate: PartialDate(1969, 8, 6),
        expiryDate: DateTime.utc(1994, 6, 23),
      ) as IcaoMrzKey;
      expect(key.information, 'L898902C<369080619406236');
      expect(key.paceReference, 1);
      expect(key.toString(), isNot(contains('L898')));
    });

    test('pads a short number and keeps a long one whole', () {
      final short = IcaoMrzKey(
        documentNumber: 'ab12',
        birthDate: PartialDate(1990, 5, 15),
        expiryDate: DateTime.utc(2034, 3, 13),
      );
      expect(short.information.substring(0, 9), 'AB12<<<<<');
      final long = IcaoMrzKey(
        documentNumber: '592123456789',
        birthDate: PartialDate(1990, 5, 15),
        expiryDate: DateTime.utc(2034, 3, 13),
      );
      expect(long.information, startsWith('5921234567891'));
    });

    test('keeps an overflowing number whole, as the ICAO example does', () {
      // ICAO 9303 part 11, appendix D.2, TD1 with a 12 character number.
      const mrz = 'I<UTOD23145890<7349<<<<<<<<<<<\n'
          '3407127M9507122UTO<<<<<<<<<<<2\n'
          'STEVENSON<<PETER<JOHN<<<<<<<<<';
      final key = IcaoAccessKey.fromMrz(mrz) as IcaoMrzKey;
      expect(key.information, 'D23145890734934071279507122');
    });

    test('reads the key out of a whole MRZ', () {
      final key = IcaoAccessKey.fromMrz(_td3) as IcaoMrzKey;
      expect(key.information, 'L898902C3674081221204159');
    });

    test('takes a CAN of digits only', () {
      expect(IcaoAccessKey.can('123 456').paceSecret, '123456'.codeUnits);
      expect(IcaoAccessKey.can('123456').paceReference, 2);
      expect(() => IcaoAccessKey.can('12a456'), throwsArgumentError);
    });
  });
}
