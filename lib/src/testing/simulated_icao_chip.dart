import 'dart:convert';
import 'dart:typed_data';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/access_key.dart';
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/certificate.dart';
import 'package:eid_icao/src/crypto/agreement.dart';
import 'package:eid_icao/src/crypto/cipher.dart';
import 'package:eid_icao/src/crypto/hash.dart';
import 'package:eid_icao/src/crypto/named_parameters.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/crypto/signature.dart';
import 'package:eid_icao/src/image.dart';
import 'package:eid_icao/src/lds.dart';
import 'package:eid_icao/src/mrz.dart';
import 'package:eid_icao/src/reader.dart';
import 'package:eid_icao/src/security_infos.dart';
import 'package:eid_icao/src/simulated_transport.dart';
import 'package:eid_icao/src/testing/simulated_pki.dart';
import 'package:eid_icao/src/testing/specimen_photo.dart';
import 'package:eid_icao/src/tlv.dart';

/// How a simulated chip proves it is genuine.
enum SimulatedChipProof {
  /// Chip Authentication, ECDH with AES, its key in DG14.
  chipAuthentication,

  /// PACE with Chip Authentication Mapping, its key in EF.CardSecurity.
  chipAuthenticationMapping,

  /// Active Authentication with an EC key in DG15, plain ECDSA.
  activeAuthenticationEc,

  /// Active Authentication with an RSA key in DG15, ISO 9796-2.
  activeAuthenticationRsa,

  /// No proof, as on older passports.
  none,
}

/// How a simulated chip may be opened.
enum SimulatedChipAccess {
  /// PACE and BAC, as on passports issued in the 2010s and later.
  paceAndBac,

  /// PACE only, as on EU identity cards issued since August 2021.
  paceOnly,

  /// BAC only, as on the first electronic passports.
  bacOnly,
}

/// A passport or identity card chip in memory that answers the commands of
/// a real one, to test without a document or reader. Pass it wherever a
/// [CardTransport] goes:
///
/// ```dart
/// final chip = SimulatedIcaoChip(lastName: 'PEETERS', can: '654321');
/// final document = await IcaoReader(chip).read(
///   access: IcaoAccessKey.can('654321'),
/// );
/// ```
///
/// It holds the data of a fictional holder of Utopia, the state of the ICAO
/// specimens, signed by a made-up CSCA that an [IcaoReader] trusts for
/// simulated chips only.
final class SimulatedIcaoChip
    implements CardTransport, CardTerminal, SimulatedTransport {
  /// A chip holding the given data, by default that of a fictional citizen.
  ///
  /// Names are given as in the MRZ, upper case. [birthPlace] and [address]
  /// go into DG11, [issuingAuthority] and [issueDate] into DG12. A
  /// [personalNumber] goes into the optional data of the MRZ, as Belgium
  /// puts the national number there, and into DG11.
  ///
  /// [tamperedGroup] is changed after signing, so Passive Authentication
  /// fails. A [cloned] chip fails its [proof]. [latency] delays every
  /// answer.
  SimulatedIcaoChip({
    this.type = IcaoDocumentType.passport,
    String? documentNumber,
    String issuingState = 'UTO',
    String nationality = 'UTO',
    String lastName = 'SPECIMEN',
    String firstNames = 'ALICE MARIE',
    PartialDate? birthDate,
    Sex sex = Sex.female,
    DateTime? expiryDate,
    String? birthPlace = 'ZENITH<UTOPIA',
    String? address = 'AVENUE DES NATIONS 1<1000 ZENITH<UTOPIA',
    String? issuingAuthority = 'MINISTRY OF FOREIGN AFFAIRS',
    DateTime? issueDate,
    String? personalNumber,
    Uint8List? photo,
    this.faceEncoding = IcaoFaceEncoding.iso19794,
    this.can = '123456',
    this.access = SimulatedChipAccess.paceAndBac,
    this.proof = SimulatedChipProof.chipAuthentication,
    this.cloned = false,
    IcaoDataGroup? tamperedGroup,
    this.latency = Duration.zero,
  })  : documentNumber = documentNumber ??
            (type == IcaoDocumentType.passport ? 'UT1234567' : 'UTD123456'),
        birthDate = birthDate ?? PartialDate(1990, 5, 15),
        expiryDate = expiryDate ?? DateTime.utc(2034, 3, 13) {
    final mrz = _mrz(
      type: type,
      number: this.documentNumber,
      state: issuingState,
      nationality: nationality,
      lastName: lastName,
      firstNames: firstNames,
      birthDate: this.birthDate,
      sex: sex,
      expiryDate: this.expiryDate,
      personalNumber: personalNumber ?? '',
    );
    final face = photo ?? specimenPhoto;
    final groups = <IcaoDataGroup, Uint8List>{
      IcaoDataGroup.dg1: tlv(0x61, tlv(0x5F1F, ascii.encode(mrz))),
      IcaoDataGroup.dg2: _dg2(face, faceEncoding, sex),
      IcaoDataGroup.dg11: _dg11(
        name: '${lastName.replaceAll(' ', '<')}<<'
            '${firstNames.replaceAll(' ', '<')}',
        birthDate: this.birthDate,
        birthPlace: birthPlace,
        address: address,
        personalNumber: personalNumber,
      ),
      IcaoDataGroup.dg12: _dg12(
        issuingAuthority,
        issueDate ?? DateTime.utc(2024, 3, 14),
      ),
    };

    final dg14 = <Uint8List>[];
    if (access != SimulatedChipAccess.bacOnly) {
      dg14.add(_paceInfo(_paceOid));
    }
    switch (proof) {
      case SimulatedChipProof.chipAuthentication:
        dg14
          ..add(_chipAuthenticationInfo)
          ..add(_chipAuthenticationKeyInfo);
      case SimulatedChipProof.activeAuthenticationEc:
        dg14.add(derSequence([
          derObjectIdentifier(activeAuthenticationOid),
          derInteger(BigInt.one),
          derObjectIdentifier('0.4.0.127.0.7.1.1.4.1.3'),
        ]));
        groups[IcaoDataGroup.dg15] = tlv(
          0x6F,
          SimulatedPki.subjectPublicKeyInfo(
            SimulatedPki.publicKeyOf(_activeEcKey),
          ),
        );
      case SimulatedChipProof.activeAuthenticationRsa:
        groups[IcaoDataGroup.dg15] =
            tlv(0x6F, rsaSubjectPublicKeyInfo(_rsaKey));
      case SimulatedChipProof.chipAuthenticationMapping:
      case SimulatedChipProof.none:
    }
    if (dg14.isNotEmpty) groups[IcaoDataGroup.dg14] = tlv(0x6E, derSet(dg14));

    final pki = SimulatedPki.instance;
    final sorted = groups.keys.toList()
      ..sort((a, b) => a.number.compareTo(b.number));
    final lds = derSequence([
      derInteger(BigInt.zero),
      derSequence([
        derObjectIdentifier(HashAlgorithm.sha256.objectIdentifier),
      ]),
      derSequence([
        for (final group in sorted)
          derSequence([
            derInteger(BigInt.from(group.number)),
            derOctetString(HashAlgorithm.sha256.digest(groups[group]!)),
          ]),
      ]),
    ]);
    final sod = tlv(0x77, pki.signedData('2.23.136.1.1.1', lds));

    if (tamperedGroup != null && groups[tamperedGroup] != null) {
      final file = Uint8List.fromList(groups[tamperedGroup]!);
      if (tamperedGroup == IcaoDataGroup.dg1) {
        // A letter of the name rewritten, so that the MRZ still reads: only
        // its signature gives it away.
        final at = file.lastIndexWhere((b) => b >= 0x41 && b <= 0x5A);
        file[at] = 0x41 + (file[at] - 0x41 + 1) % 26;
      } else {
        file[file.length - 1] ^= 0x01;
      }
      groups[tamperedGroup] = file;
    }

    _application = {
      0x011E: tlv(
        0x60,
        concat([
          tlv(0x5F01, ascii.encode('0107')),
          tlv(0x5F36, ascii.encode('040000')),
          tlv(0x5C, [for (final group in sorted) group.tag]),
        ]),
      ),
      0x011D: sod,
      for (final group in sorted) group.fileId: groups[group]!,
    };
    _master = {
      if (access != SimulatedChipAccess.bacOnly)
        0x011C: derSet([_paceInfo(_paceOid)]),
      if (proof == SimulatedChipProof.chipAuthenticationMapping)
        0x011D: pki.signedData(
          '0.4.0.127.0.7.3.2.1',
          derSet([
            _paceInfo(_paceOid),
            _chipAuthenticationInfo,
            _chipAuthenticationKeyInfo,
          ]),
        ),
    };
    _mrzKey = IcaoMrzKey(
      documentNumber: this.documentNumber,
      birthDate: this.birthDate,
      expiryDate: this.expiryDate,
    );
  }

  /// The kind of document: a passport (TD3) or an identity card (TD1).
  final IcaoDocumentType type;

  /// The document number.
  final String documentNumber;

  /// The date of birth.
  final PartialDate birthDate;

  /// The date of expiry.
  final DateTime expiryDate;

  /// The card access number, for PACE.
  final String can;

  /// The protocols that open the chip.
  final SimulatedChipAccess access;

  /// How the chip proves it is genuine.
  final SimulatedChipProof proof;

  /// The encoding of the face in DG2.
  final IcaoFaceEncoding faceEncoding;

  /// Whether the chip is a copy that fails its [proof].
  final bool cloned;

  /// The delay before each answer.
  final Duration latency;

  /// The key that opens the chip from its MRZ.
  IcaoAccessKey get mrzKey => _mrzKey;

  /// The key that opens the chip from its CAN.
  IcaoAccessKey get canKey => IcaoAccessKey.can(can);

  @override
  IcaoCertificate get simulatedCsca => SimulatedPki.instance.csca;

  late final Map<int, Uint8List> _application;
  late final Map<int, Uint8List> _master;
  late final IcaoMrzKey _mrzKey;

  bool _inserted = true;
  int _insertions = 0;
  bool _applicationSelected = false;
  Uint8List? _file;
  _ChipSession? _session;
  _PaceState? _pace;
  Uint8List? _challenge;
  String? _chipAuthenticationOid;

  /// Whether the chip is on the reader. If not, [transmit] throws a
  /// [CardTransportException].
  bool get isInserted => _inserted;

  /// Whether a secure messaging session is open.
  bool get isSecured => _session != null;

  @override
  String get name => 'Simulated ICAO chip';

  /// Connects to the chip, for a `CardWatcher` or an `IcaoWatcher`.
  @override
  Future<CardConnection> connect() async {
    if (!_inserted) {
      throw const CardTransportException('No chip on the simulated reader');
    }
    return _SimulatedConnection(this, _insertions);
  }

  /// Takes the document off the reader.
  void remove() => _inserted = false;

  /// Puts the document back, which resets the chip.
  void insert() {
    _inserted = true;
    _insertions++;
    _reset();
  }

  void _reset() {
    _applicationSelected = false;
    _file = null;
    _session = null;
    _pace = null;
    _challenge = null;
    _chipAuthenticationOid = null;
  }

  @override
  Future<Uint8List> transmit(Uint8List bytes) async {
    if (latency > Duration.zero) await Future<void>.delayed(latency);
    if (!_inserted) {
      throw const CardTransportException('No chip on the simulated reader');
    }
    final CommandApdu command;
    try {
      command = CommandApdu.parse(bytes);
    } on FormatException {
      return _status(0x6700);
    }
    final session = _session;
    if (command.cla & 0x0C == 0x0C) {
      if (session == null) return _status(0x6988);
      final plain = session.unwrap(command);
      if (plain == null) {
        _reset();
        return _status(0x6988);
      }
      final (data, status) = _process(plain);
      final answer = session.wrap(data, status);
      // Chip Authentication switches keys after its answer.
      if (identical(_session, session) && session.next != null) {
        _session = session.next;
      }
      return answer;
    }
    // A plain command ends secure messaging, as on a real chip.
    _session = null;
    final (data, status) = _process(command);
    return concat([data, _status(status)]);
  }

  (Uint8List, int) _process(CommandApdu command) {
    final empty = Uint8List(0);
    switch (command.ins) {
      case 0xA4:
        return (empty, _select(command));
      case 0xB0 || 0xB1:
        return _readBinary(command);
      case 0x84:
        if (access == SimulatedChipAccess.paceOnly) return (empty, 0x6D00);
        _challenge = randomBytes(8);
        return (_challenge!, 0x9000);
      case 0x82:
        return _bacAuthenticate(command);
      case 0x22:
        return (empty, _manageSecurityEnvironment(command));
      case 0x86:
        return _generalAuthenticate(command);
      case 0x88:
        return _internalAuthenticate(command);
      default:
        return (empty, 0x6D00);
    }
  }

  int _select(CommandApdu command) {
    if (command.p1 == 0x00) {
      if (!sameBytes(command.data, const [0x3F, 0x00])) return 0x6A82;
      _applicationSelected = false;
      _file = null;
      return 0x9000;
    }
    if (command.p1 == 0x04) {
      if (!sameBytes(command.data, IcaoReader.applicationAid)) return 0x6A82;
      _applicationSelected = true;
      _file = null;
      return 0x9000;
    }
    if (command.p1 != 0x02 || command.data.length != 2) return 0x6A86;
    final id = command.data[0] << 8 | command.data[1];
    final files = _applicationSelected ? _application : _master;
    final file = files[id];
    if (file == null) return 0x6A82;
    // The data groups need secure messaging; EF.CardAccess does not.
    if (_applicationSelected && _session == null) return 0x6982;
    _file = file;
    return 0x9000;
  }

  (Uint8List, int) _readBinary(CommandApdu command) {
    final file = _file;
    if (file == null) return (Uint8List(0), 0x6986);
    final odd = command.ins == 0xB1;
    final offset = odd
        ? command.data.skip(2).fold(0, (value, byte) => value << 8 | byte)
        : command.p1 << 8 | command.p2;
    if (offset > file.length) return (Uint8List(0), 0x6B00);
    var length = command.le ?? 256;
    if (odd) length -= length > 0x82 ? 3 : 2;
    final end = offset + length > file.length ? file.length : offset + length;
    final data = file.sublist(offset, end);
    final status = end - offset < length ? 0x6282 : 0x9000;
    return (odd ? tlv(0x53, data) : data, status);
  }

  (Uint8List, int) _bacAuthenticate(CommandApdu command) {
    final challenge = _challenge;
    _challenge = null;
    if (challenge == null || access == SimulatedChipAccess.paceOnly) {
      return (Uint8List(0), 0x6985);
    }
    const cipher = SymmetricCipher.tripleDes;
    final seed = _mrzKey.bacSeed;
    final kEnc = cipher.deriveKey(seed, 1);
    final kMac = cipher.deriveKey(seed, 2);
    if (command.data.length != 40) return (Uint8List(0), 0x6700);
    final cryptogram = command.data.sublist(0, 32);
    if (!sameBytes(
        cipher.macPadded(kMac, cryptogram), command.data.sublist(32))) {
      return (Uint8List(0), 0x6300);
    }
    final plain = cipher.decrypt(kEnc, cryptogram);
    if (!sameBytes(plain.sublist(8, 16), challenge)) {
      return (Uint8List(0), 0x6300);
    }
    final terminalNonce = plain.sublist(0, 8);
    final keyPart = randomBytes(16);
    final answer = cipher.encrypt(
      kEnc,
      concat([challenge, terminalNonce, keyPart]),
    );
    final seedOut = xorBytes(plain.sublist(16), keyPart);
    _session = _ChipSession(
      cipher,
      cipher.deriveKey(seedOut, 1),
      cipher.deriveKey(seedOut, 2),
      concat([challenge.sublist(4), terminalNonce.sublist(4)]),
    );
    return (concat([answer, cipher.macPadded(kMac, answer)]), 0x9000);
  }

  int _manageSecurityEnvironment(CommandApdu command) {
    Map<int, Uint8List> objects;
    try {
      objects = {
        for (final element in Tlv.parseAll(command.data))
          element.tag: element.value,
      };
    } on FormatException {
      return 0x6A80;
    }
    if (command.p1 == 0xC1 && command.p2 == 0xA4) {
      if (access == SimulatedChipAccess.bacOnly) return 0x6D00;
      final oid = decodeObjectIdentifier(objects[0x80] ?? const [0]);
      final reference = objects[0x83];
      if (oid != _paceOid || reference == null) return 0x6A80;
      final secret = switch (reference.single) {
        1 => _mrzKey.paceSecret,
        2 => IcaoAccessKey.can(can).paceSecret,
        _ => null,
      };
      if (secret == null) return 0x6A88;
      _pace = _PaceState(secret);
      return 0x9000;
    }
    if (command.p1 == 0x41 && command.p2 == 0xA4) {
      final oid = decodeObjectIdentifier(objects[0x80] ?? const [0]);
      if (proof != SimulatedChipProof.chipAuthentication ||
          oid != _chipAuthenticationOid0 ||
          _session == null) {
        return 0x6A80;
      }
      _chipAuthenticationOid = oid;
      return 0x9000;
    }
    return 0x6A86;
  }

  (Uint8List, int) _generalAuthenticate(CommandApdu command) {
    final empty = Uint8List(0);
    Tlv outer;
    try {
      outer = Tlv.parse(command.data);
    } on FormatException {
      return (empty, 0x6A80);
    }
    if (outer.tag != 0x7C) return (empty, 0x6A80);
    final objects = {for (final o in outer.children) o.tag: o.value};

    if (_chipAuthenticationOid != null && objects.containsKey(0x80)) {
      return _chipAuthenticate(objects[0x80]!);
    }

    final pace = _pace;
    if (pace == null) return (empty, 0x6985);
    final base = EcAgreement(brainpoolP256r1);
    const cipher = SymmetricCipher.aes128;
    switch (pace.step) {
      case 0:
        pace.nonce = randomBytes(16);
        pace.step = 1;
        final key = cipher.deriveKey(pace.secret, 3);
        return (
          tlv(0x7C, tlv(0x80, cipher.encrypt(key, pace.nonce!))),
          0x9000,
        );
      case 1:
        final terminal = objects[0x81];
        if (terminal == null) return (empty, 0x6A80);
        final BigInt private;
        if (proof == SimulatedChipProof.chipAuthenticationMapping) {
          // Chosen so that the mapping key is the static key times a
          // secret the chip sends at the end.
          final factor = randomBelow(brainpoolP256r1.n);
          final staticKey = cloned ? _cloneKey : _chipKey;
          private = factor * staticKey % brainpoolP256r1.n;
          pace.mappingFactor = factor;
        } else {
          private = randomBelow(brainpoolP256r1.n);
        }
        final public = base.publicKey(private);
        try {
          pace.mapped = base.mapGeneric(
            unsignedBigInt(pace.nonce!),
            private,
            terminal,
          );
        } on FormatException {
          return (empty, 0x6A80);
        }
        pace.step = 2;
        return (tlv(0x7C, tlv(0x82, public)), 0x9000);
      case 2:
        final terminal = objects[0x83];
        if (terminal == null) return (empty, 0x6A80);
        final mapped = pace.mapped!;
        final (private, public) = mapped.generateKeyPair();
        try {
          final secret = mapped.sharedSecret(private, terminal);
          pace
            ..encryptionKey = cipher.deriveKey(secret, 1)
            ..macKey = cipher.deriveKey(secret, 2)
            ..terminalKey = terminal
            ..chipKey = public
            ..step = 3;
        } on FormatException {
          return (empty, 0x6A80);
        }
        return (tlv(0x7C, tlv(0x84, public)), 0x9000);
      case 3:
        _pace = null;
        final token = objects[0x85];
        final mapped = pace.mapped!;
        final expected = cipher.authenticationToken(
          pace.macKey!,
          mapped.publicKeyDataObject(_paceOid, pace.chipKey!),
        );
        if (token == null || !sameBytes(token, expected)) {
          return (empty, 0x6300);
        }
        final answer = <List<int>>[
          tlv(
            0x86,
            cipher.authenticationToken(
              pace.macKey!,
              mapped.publicKeyDataObject(_paceOid, pace.terminalKey!),
            ),
          ),
        ];
        final factor = pace.mappingFactor;
        if (factor != null) {
          final iv = cipher.encryptBlock(
            pace.encryptionKey!,
            Uint8List(16)..fillRange(0, 16, 0xFF),
          );
          answer.add(tlv(
            0x8A,
            cipher.encrypt(
              pace.encryptionKey!,
              pad(bigIntBytes(factor, brainpoolP256r1.size), 16),
              iv: iv,
            ),
          ));
        }
        _session = _ChipSession(
          cipher,
          pace.encryptionKey!,
          pace.macKey!,
          Uint8List(16),
        );
        return (tlv(0x7C, concat(answer)), 0x9000);
      default:
        return (empty, 0x6985);
    }
  }

  (Uint8List, int) _chipAuthenticate(Uint8List terminalKey) {
    _chipAuthenticationOid = null;
    final session = _session!;
    const cipher = SymmetricCipher.aes128;
    final Uint8List secret;
    try {
      secret = EcAgreement(brainpoolP256r1).sharedSecret(
        cloned ? _cloneKey : _chipKey,
        terminalKey,
      );
    } on FormatException {
      return (Uint8List(0), 0x6A80);
    }
    // This answer goes under the old keys; the next under the new.
    session.next = _ChipSession(
      cipher,
      cipher.deriveKey(secret, 1),
      cipher.deriveKey(secret, 2),
      Uint8List(16),
    );
    return (tlv(0x7C, const []), 0x9000);
  }

  (Uint8List, int) _internalAuthenticate(CommandApdu command) {
    final challenge = command.data;
    switch (proof) {
      case SimulatedChipProof.activeAuthenticationEc:
        final key = cloned ? _cloneKey : _activeEcKey;
        final (r, s) = signEcdsa(
          SimulatedPki.publicKeyOf(key),
          key,
          HashAlgorithm.sha256.digest(challenge),
        );
        return (
          concat([bigIntBytes(r, 32), bigIntBytes(s, 32)]),
          0x9000,
        );
      case SimulatedChipProof.activeAuthenticationRsa:
        final k = _rsaKey.size;
        final m1 = randomBytes(k - 20 - 2);
        final f = concat([
          const [0x6A],
          m1,
          HashAlgorithm.sha1.digest(concat([m1, challenge])),
          const [0xBC],
        ]);
        if (cloned) f[5] ^= 1;
        return (rsaSeal(_rsaKey, _rsaPrivate, f), 0x9000);
      case SimulatedChipProof.chipAuthentication:
      case SimulatedChipProof.chipAuthenticationMapping:
      case SimulatedChipProof.none:
        return (Uint8List(0), 0x6D00);
    }
  }

  static Uint8List _status(int statusWord) =>
      Uint8List.fromList([statusWord >> 8, statusWord & 0xFF]);

  static const _paceGm = '0.4.0.127.0.7.2.2.4.2.2';
  static const _paceCam = '0.4.0.127.0.7.2.2.4.6.2';
  static const _chipAuthenticationOid0 = '0.4.0.127.0.7.2.2.3.2.2';

  String get _paceOid => proof == SimulatedChipProof.chipAuthenticationMapping
      ? _paceCam
      : _paceGm;

  static Uint8List _paceInfo(String oid) => derSequence([
        derObjectIdentifier(oid),
        derInteger(BigInt.two),
        derInteger(BigInt.from(13)),
      ]);

  static final _chipAuthenticationInfo = derSequence([
    derObjectIdentifier(_chipAuthenticationOid0),
    derInteger(BigInt.two),
  ]);

  static final _chipAuthenticationKeyInfo = derSequence([
    derObjectIdentifier('0.4.0.127.0.7.2.2.1.2'),
    SimulatedPki.subjectPublicKeyInfo(SimulatedPki.publicKeyOf(_chipKey)),
  ]);

  static final _chipKey = BigInt.parse(
    '468acc7c7b751a45eb118ebcdb6bfded14185d0be202944483d644118968186d',
    radix: 16,
  );
  static final _activeEcKey = BigInt.parse(
    '5ddd954ebcf5c7a2a04a16bba0664ce936e506b2a41e532e114e663be123cc83',
    radix: 16,
  );
  static final _cloneKey = BigInt.parse('1234567890abcdef', radix: 16);
  static final _rsaKey = RsaPublicKey(
    BigInt.parse(
      'ba4719bf9a7608b1c0e2bf887c3a08524210ecd760cd5edbf7f08eea127bc163'
      '063e3f9db7c8f2f786b04a690e27925322083d237fa102cd5177728c5a3fbc87'
      'd85cab8e92fdafbadeb08465e0594b67c5f66a79c14327f6e0a66e4722067641'
      'c91fc3b7e6bf6bf5f31b9a2c634dd7b40570860a7614ac773a0d1d1e4781bc37',
      radix: 16,
    ),
    BigInt.from(65537),
  );
  static final _rsaPrivate = BigInt.parse(
    '5a3fe871b45c4b8a1371c86a5005add26cbfd67fe31e9d3ee5b95f0479400c49'
    'f5d462edff0514f268073186049d977f3f95ce494ca4adbedc218b160503ac4b'
    '3124c7f0573f825d77d5f0e3d75a732f8f996a7771893a5d2f99e9373d21c3c8'
    'b0c41a27614f0ba59d8e4f51056aec96a098f688a7e5f69338a6b7b6631395c1',
    radix: 16,
  );
}

// The chip's side of secure messaging.
final class _ChipSession {
  _ChipSession(this.cipher, this.encryptionKey, this.macKey, Uint8List ssc)
      : ssc = Uint8List.fromList(ssc);

  final SymmetricCipher cipher;
  final Uint8List encryptionKey;
  final Uint8List macKey;
  final Uint8List ssc;

  // The session after Chip Authentication, from the next command on.
  _ChipSession? next;

  void _increment() {
    for (var i = ssc.length - 1; i >= 0; i--) {
      ssc[i] = (ssc[i] + 1) & 0xFF;
      if (ssc[i] != 0) return;
    }
  }

  Uint8List? _iv() =>
      cipher.isAes ? cipher.encryptBlock(encryptionKey, ssc) : null;

  // The plain command, or null when its MAC fails.
  CommandApdu? unwrap(CommandApdu command) {
    _increment();
    final List<Tlv> objects;
    try {
      objects = Tlv.parseAll(command.data);
    } on FormatException {
      return null;
    }
    Tlv? find(int tag) => objects.where((o) => o.tag == tag).firstOrNull;
    final data = find(0x87) ?? find(0x85);
    final le = find(0x97);
    final mac = find(0x8E);
    if (mac == null) return null;
    final header = pad(
      [command.cla, command.ins, command.p1, command.p2],
      cipher.blockSize,
    );
    final expected = cipher.macPadded(
      macKey,
      concat([
        ssc,
        header,
        if (data != null) data.encoded,
        if (le != null) le.encoded
      ]),
    );
    if (!sameBytes(expected, mac.value)) return null;
    var plain = Uint8List(0);
    if (data != null) {
      final encrypted = data.tag == 0x87 ? data.value.sublist(1) : data.value;
      plain = unpad(cipher.decrypt(encryptionKey, encrypted, iv: _iv()));
    }
    int? expectedLength;
    if (le != null) {
      final value = unsignedBigInt(le.value).toInt();
      expectedLength =
          value == 0 ? (le.value.length == 1 ? 256 : 0x10000) : value;
    }
    return CommandApdu(
      command.cla & ~0x0C,
      command.ins,
      command.p1,
      command.p2,
      data: plain,
      le: expectedLength,
    );
  }

  // The protected answer. Switches to [next] afterwards.
  Uint8List wrap(Uint8List data, int status) {
    _increment();
    final dataObject = data.isEmpty
        ? Uint8List(0)
        : tlv(0x87, [
            0x01,
            ...cipher.encrypt(encryptionKey, pad(data, cipher.blockSize),
                iv: _iv()),
          ]);
    final statusObject = tlv(0x99, [status >> 8, status & 0xFF]);
    final mac =
        cipher.macPadded(macKey, concat([ssc, dataObject, statusObject]));
    return concat([
      dataObject,
      statusObject,
      tlv(0x8E, mac),
      [status >> 8, status & 0xFF],
    ]);
  }
}

final class _PaceState {
  _PaceState(this.secret);

  final Uint8List secret;
  int step = 0;
  Uint8List? nonce;
  Agreement? mapped;
  BigInt? mappingFactor;
  Uint8List? encryptionKey;
  Uint8List? macKey;
  Uint8List? terminalKey;
  Uint8List? chipKey;
}

final class _SimulatedConnection implements CardConnection, SimulatedTransport {
  _SimulatedConnection(this.chip, this._insertion);

  final SimulatedIcaoChip chip;

  // The insertion this connection reaches; it dies with it, as on a reader.
  final int _insertion;
  bool _released = false;

  @override
  IcaoCertificate get simulatedCsca => chip.simulatedCsca;

  @override
  Future<Uint8List> transmit(Uint8List command) {
    if (_released || chip._insertions != _insertion || !chip._inserted) {
      return Future.error(
        const CardTransportException('The chip left the reader'),
      );
    }
    return chip.transmit(command);
  }

  @override
  Future<void> disconnect() async => _released = true;
}

String _mrz({
  required IcaoDocumentType type,
  required String number,
  required String state,
  required String nationality,
  required String lastName,
  required String firstNames,
  required PartialDate birthDate,
  required Sex sex,
  required DateTime expiryDate,
  required String personalNumber,
}) {
  String fill(String text, int length) => text.length >= length
      ? text.substring(0, length)
      : text.padRight(length, '<');
  String field(String text) => text.toUpperCase().replaceAll(' ', '<');
  final names = '${field(lastName)}<<${field(firstNames)}';
  final birth = mrzDate(birthDate);
  final expiry =
      mrzDate(PartialDate(expiryDate.year, expiryDate.month, expiryDate.day));
  final sexLetter = switch (sex) {
    Sex.male => 'M',
    Sex.female => 'F',
    Sex.unspecified => '<',
  };
  final birthField = '$birth${mrzCheckDigit(birth)}';
  final expiryField = '$expiry${mrzCheckDigit(expiry)}';
  if (type == IcaoDocumentType.passport) {
    final line1 = fill('P<${fill(state, 3)}$names', 44);
    final numberField = '${fill(number, 9)}${mrzCheckDigit(fill(number, 9))}';
    final personal = fill(personalNumber, 14);
    final personalCheck =
        personalNumber.isEmpty ? '<' : '${mrzCheckDigit(personal)}';
    final body = '$numberField${fill(nationality, 3)}$birthField$sexLetter'
        '$expiryField$personal$personalCheck';
    final composite = mrzCheckDigit(
      '$numberField$birthField$expiryField$personal$personalCheck',
    );
    return '$line1\n$body$composite';
  }
  final String numberField;
  if (number.length > 9) {
    numberField = '${number.substring(0, 9)}<${number.substring(9)}'
        '${mrzCheckDigit(number)}';
  } else {
    numberField = '${fill(number, 9)}${mrzCheckDigit(fill(number, 9))}';
  }
  final line1 = fill('ID${fill(state, 3)}$numberField', 30);
  final optional = fill(personalNumber, 11);
  final composite = mrzCheckDigit(
    '${line1.substring(5)}$birthField$expiryField$optional',
  );
  final line2 = '$birthField$sexLetter$expiryField${fill(nationality, 3)}'
      '$optional$composite';
  return '$line1\n$line2\n${fill(names, 30)}';
}

Uint8List _dg2(Uint8List photo, IcaoFaceEncoding encoding, Sex sex) {
  final sniffed = IcaoImage.sniff(photo);
  final image = (sniffed.width ?? 0, sniffed.height ?? 0);
  final jpeg2000 = sniffed.format == IcaoImageFormat.jpeg2000;
  final Uint8List block;
  if (encoding == IcaoFaceEncoding.iso19794) {
    final record = concat([
      _u32(20 + 12 + photo.length),
      _u16(0),
      [switch (sex) {  Sex.male => 1, Sex.female => 2, Sex.unspecified => 0}],
      [0, 0],
      [0, 0, 0],
      _u16(0),
      [0, 0, 0],
      [0, 0, 0],
      // Full frontal, JPEG or JPEG 2000, size, 24 bit RGB, static photo,
      // unknown device, unspecified quality.
      [1, if (jpeg2000) 1 else 0],
      _u16(image.$1),
      _u16(image.$2),
      [1, 2],
      _u16(0),
      _u16(0),
      photo,
    ]);
    block = tlv(
      0x5F2E,
      concat([
        ascii.encode('FAC\u0000010\u0000'),
        _u32(14 + record.length),
        _u16(1),
        record,
      ]),
    );
  } else {
    // ISO/IEC 39794-5, implicit tags; see the notice in face_39794.dart.
    BigInt big(int value) => BigInt.from(value);
    Uint8List integer(int tag, int value) =>
        tlv(tag, derInteger(big(value)).sublist(2));
    block = tlv(
      0x5F2E,
      tlv(
        0x65,
        concat([
          tlv(0xA0, concat([integer(0x80, 3), integer(0x81, 2019)])),
          tlv(
            0xA1,
            derSequence([
              integer(0x80, 1),
              tlv(
                0xA1,
                tlv(
                  0xA0,
                  tlv(
                    0xA0,
                    concat([
                      tlv(0x80, photo),
                      tlv(
                        0xA1,
                        concat([
                          // JPEG, or lossy JPEG 2000.
                          tlv(0xA0, integer(0x80, jpeg2000 ? 3 : 2)),
                          tlv(
                            0xA7,
                            concat([
                              integer(0x80, image.$1),
                              integer(0x81, image.$2),
                            ]),
                          ),
                        ]),
                      ),
                    ]),
                  ),
                ),
              ),
            ]),
          ),
        ]),
      ),
    );
  }
  final formatType =
      encoding == IcaoFaceEncoding.iso19794 ? [0x00, 0x08] : [0x00, 0x40];
  return tlv(
    0x75,
    tlv(
      0x7F61,
      concat([
        tlv(0x02, const [1]),
        tlv(
          0x7F60,
          concat([
            tlv(
              0xA1,
              concat([
                tlv(0x80, const [0x01, 0x01]),
                tlv(0x81, const [0x02]),
                tlv(0x87, const [0x01, 0x01]),
                tlv(0x88, formatType),
              ]),
            ),
            block,
          ]),
        ),
      ]),
    ),
  );
}

Uint8List _dg11({
  required String name,
  required PartialDate birthDate,
  required String? birthPlace,
  required String? address,
  required String? personalNumber,
}) {
  final date = '${birthDate.year.toString().padLeft(4, '0')}'
      '${(birthDate.month ?? 0).toString().padLeft(2, '0')}'
      '${(birthDate.day ?? 0).toString().padLeft(2, '0')}';
  final fields = <int, List<int>>{
    0x5F0E: utf8.encode(name),
    0x5F2B: ascii.encode(date),
    if (personalNumber != null) 0x5F10: ascii.encode(personalNumber),
    if (birthPlace != null) 0x5F11: utf8.encode(birthPlace),
    if (address != null) 0x5F42: utf8.encode(address),
  };
  return tlv(
    0x6B,
    concat([
      tlv(0x5C, [
        for (final tag in fields.keys) ...[tag >> 8, tag & 0xFF]
      ]),
      for (final MapEntry(:key, :value) in fields.entries) tlv(key, value),
    ]),
  );
}

Uint8List _dg12(String? authority, DateTime issued) {
  String digits(DateTime time, {bool withTime = false}) {
    String two(int value) => value.toString().padLeft(2, '0');
    final date = '${time.year}${two(time.month)}${two(time.day)}';
    return withTime
        ? '$date${two(time.hour)}${two(time.minute)}${two(time.second)}'
        : date;
  }

  final fields = <int, List<int>>{
    if (authority != null) 0x5F19: utf8.encode(authority),
    0x5F26: ascii.encode(digits(issued)),
    0x5F55: ascii.encode(
      digits(issued.subtract(const Duration(days: 7)), withTime: true),
    ),
  };
  return tlv(
    0x6C,
    concat([
      tlv(0x5C, [
        for (final tag in fields.keys) ...[tag >> 8, tag & 0xFF]
      ]),
      for (final MapEntry(:key, :value) in fields.entries) tlv(key, value),
    ]),
  );
}

List<int> _u16(int value) => [value >> 8 & 0xFF, value & 0xFF];

List<int> _u32(int value) =>
    [value >> 24 & 0xFF, value >> 16 & 0xFF, value >> 8 & 0xFF, value & 0xFF];
