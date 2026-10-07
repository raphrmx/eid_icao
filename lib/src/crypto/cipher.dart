import 'dart:typed_data';

import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/hash.dart';
import 'package:pointycastle/api.dart';
import 'package:pointycastle/block/aes.dart';
import 'package:pointycastle/block/desede_engine.dart';

/// The block ciphers of ICAO 9303 secure messaging, each with its MAC:
/// 3DES with the retail MAC, AES with CMAC.
enum SymmetricCipher {
  /// Two-key 3DES in CBC mode, ISO 9797-1 MAC algorithm 3.
  tripleDes(16, 8),

  /// AES-128 in CBC mode, CMAC.
  aes128(16, 16),

  /// AES-192 in CBC mode, CMAC.
  aes192(24, 16),

  /// AES-256 in CBC mode, CMAC.
  aes256(32, 16);

  const SymmetricCipher(this.keyLength, this.blockSize);

  /// The key length in bytes.
  final int keyLength;

  /// The block length in bytes.
  final int blockSize;

  /// Whether this is an AES cipher.
  bool get isAes => this != tripleDes;

  /// Derives key [counter] from the shared [secret], ICAO 9303 part 11:
  /// 1 for encryption, 2 for MAC, 3 for the PACE password key.
  Uint8List deriveKey(List<int> secret, int counter) {
    final input = concat([
      secret,
      [
        counter >> 24 & 0xFF,
        counter >> 16 & 0xFF,
        counter >> 8 & 0xFF,
        counter & 0xFF
      ],
    ]);
    final hash = keyLength <= 16 ? HashAlgorithm.sha1 : HashAlgorithm.sha256;
    return Uint8List.sublistView(hash.digest(input), 0, keyLength);
  }

  /// [data], a whole number of blocks, encrypted in CBC mode.
  Uint8List encrypt(List<int> key, List<int> data, {List<int>? iv}) =>
      _cbc(key, data, iv, encrypt: true);

  /// [data], a whole number of blocks, decrypted in CBC mode.
  Uint8List decrypt(List<int> key, List<int> data, {List<int>? iv}) =>
      _cbc(key, data, iv, encrypt: false);

  /// One [block] encrypted alone.
  Uint8List encryptBlock(List<int> key, List<int> block) =>
      _engine(key, encrypt: true).process(Uint8List.fromList(block));

  /// The 8 byte MAC of [data] padded with ISO 9797-1 method 2, as secure
  /// messaging and BAC compute it.
  Uint8List macPadded(List<int> key, List<int> data) =>
      _mac(key, pad(data, blockSize));

  /// The 8 byte PACE authentication token of [data]: padded for 3DES, as is
  /// for CMAC.
  Uint8List authenticationToken(List<int> key, List<int> data) =>
      isAes ? _mac(key, data) : macPadded(key, data);

  Uint8List _mac(List<int> key, List<int> data) {
    if (isAes) return Uint8List.sublistView(_cmac(key, data), 0, 8);
    // Retail MAC: single DES CBC with the first key, then the last block
    // through the full 3DES.
    if (data.length % 8 != 0) {
      throw ArgumentError.value(data.length, 'data.length', 'Not padded');
    }
    final first = key.sublist(0, 8);
    final single = _engine([...first, ...first], encrypt: true);
    final triple = _engine(key, encrypt: true);
    var state = Uint8List(8);
    for (var offset = 0; offset < data.length; offset += 8) {
      final block = xorBytes(state, data.sublist(offset, offset + 8));
      state = offset + 8 < data.length
          ? single.process(block)
          : triple.process(block);
    }
    return state;
  }

  // AES-CMAC, RFC 4493. pointycastle's CMac takes an IV as long as the key,
  // which breaks AES-192 and AES-256.
  Uint8List _cmac(List<int> key, List<int> data) {
    final engine = _engine(key, encrypt: true);
    Uint8List twice(Uint8List block) {
      final out = Uint8List(16);
      for (var i = 0; i < 16; i++) {
        out[i] = (block[i] << 1 | (i < 15 ? block[i + 1] >> 7 : 0)) & 0xFF;
      }
      if (block[0] & 0x80 != 0) out[15] ^= 0x87;
      return out;
    }

    final k1 = twice(engine.process(Uint8List(16)));
    final k2 = twice(k1);
    final blocks = data.isEmpty ? 1 : (data.length + 15) ~/ 16;
    final complete = data.isNotEmpty && data.length % 16 == 0;
    var state = Uint8List(16);
    for (var n = 0; n < blocks; n++) {
      final start = n * 16;
      var block = Uint8List(16)
        ..setRange(
          0,
          (data.length - start).clamp(0, 16),
          data.skip(start).take(16),
        );
      if (n == blocks - 1) {
        if (!complete) block[data.length - start] = 0x80;
        block = xorBytes(block, complete ? k1 : k2);
      }
      state = engine.process(xorBytes(state, block));
    }
    return state;
  }

  Uint8List _cbc(
    List<int> key,
    List<int> data,
    List<int>? iv, {
    required bool encrypt,
  }) {
    if (data.length % blockSize != 0) {
      throw ArgumentError.value(data.length, 'data.length', 'Not padded');
    }
    final engine = _engine(key, encrypt: encrypt);
    final out = Uint8List(data.length);
    var chain = Uint8List.fromList(iv ?? Uint8List(blockSize));
    for (var offset = 0; offset < data.length; offset += blockSize) {
      final block = Uint8List.fromList(
        data.sublist(offset, offset + blockSize),
      );
      if (encrypt) {
        chain = engine.process(xorBytes(chain, block));
        out.setRange(offset, offset + blockSize, chain);
      } else {
        out.setRange(
          offset,
          offset + blockSize,
          xorBytes(chain, engine.process(block)),
        );
        chain = block;
      }
    }
    return out;
  }

  BlockCipher _engine(List<int> key, {required bool encrypt}) {
    if (key.length != keyLength && !(this == tripleDes && key.length == 24)) {
      throw ArgumentError.value(key.length, 'key.length');
    }
    return (isAes ? AESEngine() : DESedeEngine())
      ..init(encrypt, KeyParameter(Uint8List.fromList(key)));
  }
}

/// [data] padded with ISO 9797-1 method 2 to a multiple of [blockSize]:
/// 80, then zeros.
Uint8List pad(List<int> data, int blockSize) {
  final length = (data.length ~/ blockSize + 1) * blockSize;
  return Uint8List(length)
    ..setRange(0, data.length, data)
    ..[data.length] = 0x80;
}

/// [data] without its ISO 9797-1 method 2 padding.
///
/// Throws a [FormatException] when the padding is missing.
Uint8List unpad(Uint8List data) {
  var end = data.length - 1;
  while (end >= 0 && data[end] == 0) {
    end--;
  }
  if (end < 0 || data[end] != 0x80) {
    throw const FormatException('Bad padding');
  }
  return Uint8List.sublistView(data, 0, end);
}
