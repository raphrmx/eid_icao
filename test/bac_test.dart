import 'package:eid/eid.dart';
import 'package:eid_icao/src/access_key.dart';
import 'package:eid_icao/src/bac.dart';
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/exceptions.dart';
import 'package:test/test.dart';

import 'scripted_transport.dart';

// ICAO 9303 part 11, appendix D: BAC, then secure messaging reading EF.COM.
// The answers and commands are long hex strings, split over lines.
// ignore_for_file: no_adjacent_strings_in_list

void main() {
  final key = IcaoMrzKey(
    documentNumber: 'L898902C<',
    birthDate: PartialDate(1969, 8, 6),
    expiryDate: DateTime.utc(1994, 6, 23),
  );

  test('opens the chip and reads EF.COM as the worked example does', () async {
    final transport = ScriptedTransport([
      '4608F91988702212 9000',
      '46B9342A41396CD7386BF5803104D7CEDC122B9132139BAF2EEDC94EE178534F'
          '2F2D235D074D7449 9000',
      '990290008E08FA855A5D4C50A8ED 9000',
      '8709019FF0EC34F9922651990290008E08AD55CC17140B2DED 9000',
      '871901FB9235F4E4037F2327DCC8964F1F9B8C30F42C8E2FFF224A99029000'
          '8E08C8B2787EAEA07D74 9000',
    ]);
    final raw = CardChannel(transport);
    final session = await performBac(
      raw,
      key,
      terminalNonce: hexBytes('781723860C06C226'),
      terminalKey: hexBytes('0B795240CB7049B01C19B33E32804F0B'),
    );
    expect(hexString(session.ssc), '887022120C06C226');

    final channel = CardChannel(session);
    await channel.selectFile(0x011E);
    final head = await channel.readBinary(offset: 0, length: 4);
    expect(hexString(head), '60145F01');
    final rest = await channel.readBinary(offset: 4, length: 0x12);
    expect(hexString(rest), '04303130365F36063034303030305C026175');

    expect(transport.sent, [
      '0084000008',
      '0082000028'
          '72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2'
          '5F1448EEA8AD90A728',
      '0CA4020C158709016375432908C044F68E08BF8B92D635FF24F800',
      '0CB000000D9701048E08ED6705417E96BA5500',
      '0CB000040D9701128E082EA28A70F3C7B53500',
    ]);
  });

  test('reports a wrong MRZ', () async {
    final transport = ScriptedTransport(['4608F91988702212 9000', '6300']);
    await expectLater(
      performBac(CardChannel(transport), key),
      throwsA(
        isA<IcaoAccessException>()
            .having((e) => e.reason, 'reason', IcaoAccessFailure.wrongKey),
      ),
    );
  });
}
