import 'dart:typed_data';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/crypto/cipher.dart';
import 'package:eid_icao/src/exceptions.dart';
import 'package:eid_icao/src/tlv.dart';

/// Secure messaging of ICAO 9303 part 11: a transport that encrypts and
/// MACs each command, and checks and decrypts each answer.
///
/// A `CardChannel` over it sends plain commands as usual.
final class SecureMessaging implements CardTransport {
  /// A session over [raw] with the session keys [encryptionKey] and
  /// [macKey], starting from the send sequence counter [ssc].
  SecureMessaging(
    this.raw, {
    required this.cipher,
    required Uint8List encryptionKey,
    required Uint8List macKey,
    required Uint8List ssc,
  })  : _encryptionKey = encryptionKey,
        _macKey = macKey,
        _ssc = Uint8List.fromList(ssc) {
    if (ssc.length != cipher.blockSize) {
      throw ArgumentError.value(ssc.length, 'ssc.length');
    }
  }

  /// A session with the counter at zero, as after PACE or Chip
  /// Authentication.
  SecureMessaging.fromZero(
    CardChannel raw, {
    required SymmetricCipher cipher,
    required Uint8List encryptionKey,
    required Uint8List macKey,
  }) : this(
          raw,
          cipher: cipher,
          encryptionKey: encryptionKey,
          macKey: macKey,
          ssc: Uint8List(cipher.blockSize),
        );

  /// The channel to the chip, carrying the protected commands.
  final CardChannel raw;

  /// The cipher and MAC of the session.
  final SymmetricCipher cipher;

  final Uint8List _encryptionKey;
  final Uint8List _macKey;
  final Uint8List _ssc;

  /// The send sequence counter, for tests.
  Uint8List get ssc => Uint8List.fromList(_ssc);

  @override
  Future<Uint8List> transmit(Uint8List command) async {
    final response = await raw.send(wrap(CommandApdu.parse(command)));
    return unwrap(response);
  }

  /// [command] protected: header masked, data encrypted, MAC added.
  CommandApdu wrap(CommandApdu command) {
    _increment();
    final cla = command.cla | 0x0C;
    final header =
        pad([cla, command.ins, command.p1, command.p2], cipher.blockSize);

    var dataObject = Uint8List(0);
    if (command.data.isNotEmpty) {
      final encrypted = cipher.encrypt(
        _encryptionKey,
        pad(command.data, cipher.blockSize),
        iv: _iv(),
      );
      // An odd instruction carries its data in a BER-TLV object already.
      dataObject = command.ins.isOdd
          ? tlv(0x85, encrypted)
          : tlv(0x87, [0x01, ...encrypted]);
    }

    final le = command.le;
    final expected = le == null
        ? Uint8List(0)
        : tlv(
            0x97,
            switch (le) {
              0x10000 => const [0, 0],
              > 256 => [le >> 8, le & 0xFF],
              256 => const [0],
              _ => [le],
            });

    final mac = cipher.macPadded(
      _macKey,
      concat([_ssc, header, dataObject, expected]),
    );
    final data = concat([dataObject, expected, tlv(0x8E, mac)]);
    // The protected answer is larger than the plain one: extended length
    // when it may not fit in a short one.
    final extended = data.length > 255 || _protectedSize(le ?? 0) > 256;
    return CommandApdu(
      cla,
      command.ins,
      command.p1,
      command.p2,
      data: data,
      le: extended ? 0x10000 : 256,
    );
  }

  // The largest protected answer to a plain one of [length] bytes: 87 with
  // its padding, then 99 and 8E.
  int _protectedSize(int length) {
    if (length == 0) return 14;
    final content = (length ~/ cipher.blockSize + 1) * cipher.blockSize + 1;
    final header = content < 0x80 ? 2 : (content < 0x100 ? 3 : 4);
    return header + content + 14;
  }

  /// The plain answer, data then status word, out of the protected
  /// [response].
  ///
  /// A bare error status, which some chips return, passes through; a bare
  /// success never does, since nothing vouches for it. Throws an
  /// [IcaoSecureMessagingException] when the MAC or the status object is
  /// missing, or the MAC does not hold.
  Uint8List unwrap(ResponseApdu response) {
    if (response.data.isEmpty) {
      if (response.sw1 == 0x90 || response.sw1 == 0x61) {
        throw const IcaoSecureMessagingException('Unprotected success');
      }
      return Uint8List.fromList([response.sw1, response.sw2]);
    }
    _increment();
    final List<Tlv> objects;
    try {
      objects = Tlv.parseAll(response.data);
    } on FormatException {
      throw const IcaoSecureMessagingException('Malformed protected answer');
    }
    Tlv? find(int tag) {
      for (final object in objects) {
        if (object.tag == tag) return object;
      }
      return null;
    }

    final data = find(0x87) ?? find(0x85);
    final status = find(0x99);
    final mac = find(0x8E);
    if (mac == null || status == null) {
      throw const IcaoSecureMessagingException(
        'The answer lacks its MAC or status',
      );
    }
    final expected = cipher.macPadded(
      _macKey,
      concat([
        _ssc,
        if (data != null) data.encoded,
        status.encoded,
      ]),
    );
    if (!sameBytes(expected, mac.value)) {
      throw const IcaoSecureMessagingException('The answer fails its MAC');
    }

    var plain = Uint8List(0);
    if (data != null) {
      final value = data.value;
      if (data.tag == 0x87 && (value.isEmpty || value[0] != 0x01)) {
        throw const IcaoSecureMessagingException('Unsupported padding');
      }
      final encrypted = data.tag == 0x87 ? value.sublist(1) : value;
      try {
        plain = unpad(cipher.decrypt(_encryptionKey, encrypted, iv: _iv()));
      } on Object {
        throw const IcaoSecureMessagingException('Undecipherable answer');
      }
    }
    final statusBytes = status.value;
    if (statusBytes.length != 2) {
      throw const IcaoSecureMessagingException('Malformed status object');
    }
    return concat([plain, statusBytes]);
  }

  // 3DES runs with a zero IV; AES with the encrypted counter.
  Uint8List? _iv() =>
      cipher.isAes ? cipher.encryptBlock(_encryptionKey, _ssc) : null;

  void _increment() {
    for (var i = _ssc.length - 1; i >= 0; i--) {
      _ssc[i] = (_ssc[i] + 1) & 0xFF;
      if (_ssc[i] != 0) return;
    }
  }
}
