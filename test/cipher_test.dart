import 'package:eid/eid.dart';
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/cipher.dart';
import 'package:test/test.dart';

// DES ignores the lowest bit of each key byte, which the examples set for
// odd parity.
List<int> _withoutParity(List<int> key) => [for (final b in key) b & 0xFE];

void main() {
  // ICAO 9303 part 11, appendix D.
  group('BAC worked example', () {
    const tripleDes = SymmetricCipher.tripleDes;
    final seed = hexBytes('239AB9CB282DAF66231DC5A4DF6BFBAE');
    final kEnc = tripleDes.deriveKey(seed, 1);
    final kMac = tripleDes.deriveKey(seed, 2);

    test('derives the keys', () {
      expect(
        _withoutParity(kEnc),
        _withoutParity(hexBytes('AB94FDECF2674FDFB9B391F85D7F76F2')),
      );
      expect(
        _withoutParity(kMac),
        _withoutParity(hexBytes('7962D9ECE03D1ACD4C76089DCE131543')),
      );
    });

    test('encrypts and MACs the terminal cryptogram', () {
      final s = hexBytes(
        '781723860C06C2264608F919887022120B795240CB7049B01C19B33E32804F0B',
      );
      final encrypted = tripleDes.encrypt(kEnc, s);
      expect(
        hexString(encrypted),
        '72C29C2371CC9BDB65B779B8E8D37B29ECC154AA56A8799FAE2F498F76ED92F2',
      );
      expect(
          hexString(tripleDes.macPadded(kMac, encrypted)), '5F1448EEA8AD90A7');
      expect(tripleDes.decrypt(kEnc, encrypted), s);
    });
  });

  group('AES', () {
    // NIST SP 800-38B, appendix D: every key length and message length,
    // the MAC cut to the 8 bytes ICAO keeps.
    test('computes CMAC with 128, 192 and 256 bit keys', () {
      final message = hexBytes(
        '6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51'
        '30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710',
      );
      final cases = {
        (SymmetricCipher.aes128, '2B7E151628AED2A6ABF7158809CF4F3C'): [
          'BB1D6929E95937287FA37D129B756746',
          '070A16B46B4D4144F79BDD9DD04A287C',
          'DFA66747DE9AE63030CA32611497C827',
          '51F0BEBF7E3B9D92FC49741779363CFE',
        ],
        (
          SymmetricCipher.aes192,
          '8E73B0F7DA0E6452C810F32B809079E562F8EAD2522C6B7B',
        ): [
          'D17DDF46ADAACDE531CAC483DE7A9367',
          '9E99A7BF31E710900662F65E617C5184',
          '8A1DE5BE2EB31AAD089A82E6EE908B0E',
          'A1D5DF0EED790F794D77589659F39A11',
        ],
        (
          SymmetricCipher.aes256,
          '603DEB1015CA71BE2B73AEF0857D77811F352C073B6108D72D9810A30914DFF4',
        ): [
          '028962F61B7BF89EFC6B551F4667D983',
          '28A7023F452E8F82BD4BF28D8C37C35C',
          'AAF3D8F1DE5640C232F5B169B9C911E6',
          'E1992190549F6ED5696A2C056C315410',
        ],
      };
      for (final MapEntry(key: (cipher, key), value: macs) in cases.entries) {
        for (final (index, length) in [0, 16, 40, 64].indexed) {
          expect(
            hexString(cipher.authenticationToken(
              hexBytes(key),
              message.sublist(0, length),
            )),
            macs[index].substring(0, 16),
            reason: '${cipher.name}, $length bytes',
          );
        }
      }
    });

    // NIST SP 800-38B, example 2, cut to 8 bytes.
    test('computes CMAC', () {
      final key = hexBytes('2B7E151628AED2A6ABF7158809CF4F3C');
      final data = hexBytes('6BC1BEE22E409F96E93D7E117393172A');
      expect(
        hexString(SymmetricCipher.aes128.authenticationToken(key, data)),
        '070A16B46B4D4144',
      );
    });

    // NIST SP 800-38A, F.2.1, first block.
    test('encrypts in CBC mode', () {
      final key = hexBytes('2B7E151628AED2A6ABF7158809CF4F3C');
      final iv = hexBytes('000102030405060708090A0B0C0D0E0F');
      final data = hexBytes('6BC1BEE22E409F96E93D7E117393172A');
      final encrypted = SymmetricCipher.aes128.encrypt(key, data, iv: iv);
      expect(hexString(encrypted), '7649ABAC8119B246CEE98E9B12E9197D');
      expect(SymmetricCipher.aes128.decrypt(key, encrypted, iv: iv), data);
    });
  });

  test('pads with 80 then zeros, and removes it', () {
    expect(hexString(pad([1, 2, 3], 8)), '0102038000000000');
    expect(hexString(pad(List.filled(8, 1), 8)).length, 32);
    expect(unpad(pad([1, 2, 3], 16)), [1, 2, 3]);
    expect(() => unpad(hexBytes('0102030000')), throwsFormatException);
  });
}
