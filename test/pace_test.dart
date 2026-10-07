import 'package:eid/eid.dart';
import 'package:eid_icao/src/access_key.dart';
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/cipher.dart';
import 'package:eid_icao/src/crypto/named_parameters.dart';
import 'package:eid_icao/src/exceptions.dart';
import 'package:eid_icao/src/pace.dart';
import 'package:eid_icao/src/security_infos.dart';
import 'package:test/test.dart';

import 'scripted_transport.dart';

// The answers and commands are long hex strings, split over lines.
// ignore_for_file: no_adjacent_strings_in_list, missing_whitespace_between_adjacent_strings

// ICAO 9303 part 11, appendix G: PACE ECDH Generic Mapping on
// brainpoolP256r1 with AES-128.
void main() {
  final key = IcaoMrzKey(
    documentNumber: 'T22000129',
    birthDate: PartialDate(1964, 8, 12),
    expiryDate: DateTime.utc(2010, 10, 31),
  );
  final cardAccess = hexBytes(
    '3114 3012 060A 04007F00070202040202 020102 02010D',
  );

  test('reads the PACEInfo of EF.CardAccess', () {
    final infos = SecurityInfos.parse(cardAccess);
    final info = infos.preferredPace!;
    expect(info.objectIdentifier, '0.4.0.127.0.7.2.2.4.2.2');
    expect(info.version, 2);
    expect(info.parameterId, 13);
    expect(info.mapping, PaceMapping.generic);
    expect(info.cipher, SymmetricCipher.aes128);
    expect(infos.domainParametersOf(info), brainpoolP256r1);
  });

  test('derives the password key', () {
    expect(key.information, 'T22000129364081251010318');
    expect(
      hexString(SymmetricCipher.aes128.deriveKey(key.paceSecret, 3)),
      '89DED1B26624EC1E634C1989302849DD',
    );
  });

  test('runs the worked example', () async {
    final transport = ScriptedTransport([
      '9000',
      '7C12 8010 95A3A016522EE98D01E76CB6B98B42C3 9000',
      '7C43 8241 04'
          '824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57'
          '30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54'
          '9000',
      '7C43 8441 04'
          '9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB'
          '7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094'
          '9000',
      '7C0A 8608 3ABB9674BCE93C08 9000',
    ]);
    final info = SecurityInfos.parse(cardAccess).preferredPace!;
    final result = await performPace(
      CardChannel(transport),
      key,
      info,
      brainpoolP256r1,
      mappingKey: BigInt.parse(
        '7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99',
        radix: 16,
      ),
      agreementKey: BigInt.parse(
        'A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595',
        radix: 16,
      ),
    );
    expect(transport.sent, [
      '0022C1A412800A04007F0007020204020283010184010D',
      '10860000027C0000',
      '10860000457C438141047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896F'
          'C70262E0C2CC5E544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF7'
          '1777A9C4922D00',
      '10860000457C438341042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122'
          'F3A5EF0D5EDD301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF'
          '850149FBB3646200',
      '008600000C7C0A8508C2B0BD78D94BA86600',
    ]);
    expect(result.session.cipher, SymmetricCipher.aes128);
    expect(hexString(result.session.ssc), '0' * 32);
  });

  test('reports a wrong key when the chip refuses the token', () async {
    final transport = ScriptedTransport([
      '9000',
      '7C12 8010 95A3A016522EE98D01E76CB6B98B42C3 9000',
      '7C43 8241 04'
          '824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F57'
          '30D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54'
          '9000',
      '7C43 8441 04'
          '9E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB'
          '7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094'
          '9000',
      '6300',
    ]);
    final info = SecurityInfos.parse(cardAccess).preferredPace!;
    await expectLater(
      performPace(
        CardChannel(transport),
        IcaoAccessKey.can('123456'),
        info,
        brainpoolP256r1,
      ),
      throwsA(
        isA<IcaoAccessException>()
            .having((e) => e.reason, 'reason', IcaoAccessFailure.wrongKey),
      ),
    );
    expect(transport.sent.first, endsWith('83010284010D'));
  });
}
