import 'dart:typed_data';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/access_key.dart';
import 'package:eid_icao/src/bac.dart';
import 'package:eid_icao/src/bytes.dart';
import 'package:eid_icao/src/certificate.dart';
import 'package:eid_icao/src/chip_authentication.dart';
import 'package:eid_icao/src/cms.dart';
import 'package:eid_icao/src/crypto/ec.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/document.dart';
import 'package:eid_icao/src/exceptions.dart';
import 'package:eid_icao/src/lds.dart';
import 'package:eid_icao/src/mrz.dart';
import 'package:eid_icao/src/pace.dart';
import 'package:eid_icao/src/passive_authentication.dart';
import 'package:eid_icao/src/secure_messaging.dart';
import 'package:eid_icao/src/security_infos.dart';
import 'package:eid_icao/src/simulated_transport.dart';
import 'package:eid_icao/src/tlv.dart';

/// Reports the share of a read done so far, from 0 to 1.
typedef IcaoReadProgress = void Function(double fraction);

/// Reads the chip of a passport or identity card, ICAO 9303.
///
/// Works over any `CardTransport` from the `eid` package: a contactless
/// reader through `eid_ccid`, or NFC. Overlapping calls run one at a time.
final class IcaoReader {
  /// A reader over [transport], reporting each command and answer to
  /// [onApdu]: under secure messaging, as they are before protection. Keys
  /// are never reported.
  IcaoReader(this.transport, {ApduListener? onApdu}) : _listener = onApdu;

  /// The AID of the LDS1 eMRTD application.
  static const applicationAid = [0xA0, 0x00, 0x00, 0x02, 0x47, 0x10, 0x01];

  /// The transport to the chip.
  final CardTransport transport;

  final ApduListener? _listener;

  // While true, answers reach the listener with their data zeroed.
  bool _hideData = false;

  // The listener of the secure channels, hiding data when asked.
  void _report(ApduExchange exchange) {
    final listener = _listener;
    if (listener == null) return;
    final response = exchange.response;
    if (!_hideData || response == null || response.length <= 2) {
      listener(exchange);
      return;
    }
    listener(ApduExchange(
      command: exchange.command,
      response: Uint8List(response.length)
        ..setRange(response.length - 2, response.length,
            response.sublist(response.length - 2)),
      time: exchange.time,
      duration: exchange.duration,
    ));
  }

  // While true, the raw channel carries protected commands and stays quiet.
  bool _secure = false;

  late final CardChannel _raw = CardChannel(
    transport,
    onApdu: _listener == null
        ? null
        : (exchange) {
            if (!_secure) _listener(exchange);
          },
  );

  Future<void> _last = Future.value();

  /// Whether the chip offers PACE, so that the CAN opens it. Reads
  /// EF.CardAccess, which needs no key.
  Future<bool> acceptsCan() => _exclusive(
        () async => (await _cardAccess())?.preferredPace != null,
      );

  /// Opens the chip with [access] and reads DG1, then the [parts] asked
  /// for (all by default).
  ///
  /// Every check is on by default. Throws an [IcaoDocumentRejectedException]
  /// when the document is expired and not [acceptExpired], when its type is
  /// not in [acceptedTypes], when [verifySignatures] fails, or when
  /// [verifyCard] finds the chip not genuine. Throws an
  /// [IcaoAccessException] when [access] does not open the chip.
  ///
  /// [trustedRoots] are the CSCAs, from an `IcaoMasterList`. Without them,
  /// Passive Authentication checks the hashes and the signature, and the
  /// chain stays unverified: a chip anyone could make passes every check. [verifyCard] needs [verifySignatures]: without
  /// it, it is skipped. [onProgress] is an estimate that only grows and
  /// ends on 1.
  ///
  /// [showPrivateData] is off by default: the personal numbers are then
  /// left out, as most uses do not need them and some states restrict
  /// them. They are the optional data of the MRZ, where Belgium puts the
  /// national register number and passports a personal number, and the
  /// personal number of DG11. The signatures are still checked on the
  /// files as read; the returned document then lacks the raw DG1 and DG11
  /// (see `IcaoDocument.withoutPrivateData`), and [onApdu] gets their
  /// answers with the data zeroed.
  ///
  /// ```dart
  /// final document = await IcaoReader(transport).read(
  ///   access: IcaoAccessKey.can('123456'),
  ///   parts: {IcaoPart.face},
  /// );
  /// ```
  Future<IcaoDocument> read({
    required IcaoAccessKey access,
    Set<IcaoPart> parts = IcaoPart.all,
    bool acceptExpired = false,
    Set<IcaoDocumentType>? acceptedTypes,
    bool verifySignatures = true,
    Iterable<IcaoCertificate>? trustedRoots,
    bool verifyCard = true,
    bool showPrivateData = false,
    IcaoReadProgress? onProgress,
  }) =>
      _exclusive(() async {
        final progress = _Progress(onProgress, {
          _Progress.access: 3000,
          if (verifyCard && verifySignatures) _Progress.chipCheck: 1500,
          0x011D: 2000,
          IcaoDataGroup.dg1.fileId: 100,
          for (final part in parts)
            part.dataGroup.fileId: part == IcaoPart.face ? 18000 : 400,
        });
        final authenticator = IcaoPassiveAuthenticator(
          trustedRoots: trustedRoots ??
              switch (transport) {
                final SimulatedTransport simulated => [simulated.simulatedCsca],
                _ => null,
              },
        );
        try {
          return await _read(
            access: access,
            parts: parts,
            acceptExpired: acceptExpired,
            acceptedTypes: acceptedTypes,
            verifySignatures: verifySignatures,
            verifyCard: verifyCard && verifySignatures,
            showPrivateData: showPrivateData,
            authenticator: authenticator,
            progress: progress,
          );
        } finally {
          _secure = false;
          _hideData = false;
        }
      });

  Future<IcaoDocument> _read({
    required IcaoAccessKey access,
    required Set<IcaoPart> parts,
    required bool acceptExpired,
    required Set<IcaoDocumentType>? acceptedTypes,
    required bool verifySignatures,
    required bool verifyCard,
    required bool showPrivateData,
    required IcaoPassiveAuthenticator authenticator,
    required _Progress progress,
  }) async {
    final (session, protocol, pace) = await _open(access);
    progress.step(_Progress.access);
    var channel = CardChannel(session, onApdu: _report);

    Uint8List? cardSecurity;
    if (pace?.info.mapping == PaceMapping.chipAuthentication) {
      // EF.CardSecurity lives in the master file, before the application.
      cardSecurity = await _readFile(channel, 0x011D, progress);
    }
    await channel.expect(
      CommandApdu(0x00, 0xA4, 0x04, 0x0C, data: applicationAid),
      'SELECT APPLICATION',
    );

    final sod = await _readFile(channel, 0x011D, progress);
    final listed = _listedGroups(sod);
    final groups = <IcaoDataGroup, Uint8List>{};
    // The files holding personal numbers stay out of the log unless shown.
    bool hides(IcaoDataGroup group) =>
        !showPrivateData &&
        (group == IcaoDataGroup.dg1 || group == IcaoDataGroup.dg11);
    _hideData = hides(IcaoDataGroup.dg1);
    groups[IcaoDataGroup.dg1] =
        await _readFile(channel, IcaoDataGroup.dg1.fileId, progress);
    _hideData = false;
    final mrz = parseDg1(groups[IcaoDataGroup.dg1]!);

    final type = mrz.documentType;
    if (acceptedTypes != null && !acceptedTypes.contains(type)) {
      throw IcaoDocumentRejectedException(IcaoRejection.documentType, mrz);
    }
    if (!acceptExpired && mrz.isExpiredOn()) {
      throw IcaoDocumentRejectedException(IcaoRejection.expired, mrz);
    }

    Future<void> readGroup(IcaoDataGroup group) async {
      if (!listed.contains(group) || groups.containsKey(group)) return;
      _hideData = hides(group);
      try {
        groups[group] = await _readFile(channel, group.fileId, progress);
      } finally {
        _hideData = false;
      }
    }

    IcaoChipAuthenticity? authenticity;
    var chipAuthenticated = false;
    if (verifyCard) {
      SecurityInfos? dg14;
      if (listed.contains(IcaoDataGroup.dg14)) {
        await readGroup(IcaoDataGroup.dg14);
        dg14 = SecurityInfos.parse(_unwrap(groups[IcaoDataGroup.dg14]!, 0x6E));
      }
      _checkDowngrade(dg14, protocol, pace, mrz);
      if (pace?.chipAuthenticationData != null) {
        authenticity = _checkMapping(pace!, cardSecurity, authenticator, mrz);
      } else if (dg14 != null) {
        final chosen = chipAuthenticationOf(dg14);
        if (chosen != null) {
          try {
            final renewed = await performChipAuthentication(
              channel,
              _raw,
              chosen.$1,
              chosen.$2,
            );
            channel = CardChannel(renewed, onApdu: _report);
            // The proof: data answered under the new keys, the start of DG1
            // as read before.
            await channel.expect(
              CommandApdu(0x00, 0xA4, 0x02, 0x0C, data: const [0x01, 0x01]),
              'SELECT FILE 0101',
            );
            final dg1 = groups[IcaoDataGroup.dg1]!;
            final length = dg1.length < 8 ? dg1.length : 8;
            final head = await channel.readBinary(offset: 0, length: length);
            if (!sameBytes(head, dg1.sublist(0, length))) {
              throw const IcaoSecureMessagingException('DG1 differs');
            }
            authenticity = IcaoChipAuthenticity.chipAuthentication;
            chipAuthenticated = true;
          } on Exception catch (error) {
            if (error is CardTransportException) rethrow;
            throw IcaoDocumentRejectedException(
              IcaoRejection.notGenuine,
              mrz,
              cause: '$error',
            );
          }
        }
      }
      progress.step(_Progress.chipCheck);
    }

    for (final part in parts) {
      await readGroup(part.dataGroup);
    }

    if (verifyCard && authenticity == null && !chipAuthenticated) {
      if (listed.contains(IcaoDataGroup.dg15)) {
        await readGroup(IcaoDataGroup.dg15);
        final key = PublicKey.parse(
          _unwrap(groups[IcaoDataGroup.dg15]!, 0x6F),
        );
        final dg14 = groups[IcaoDataGroup.dg14];
        final algorithm = dg14 == null
            ? null
            : SecurityInfos.parse(_unwrap(dg14, 0x6E))
                .activeAuthenticationSignature;
        final holds = await performActiveAuthentication(
          channel,
          key,
          ecdsaAlgorithm: algorithm,
        );
        if (!holds) {
          throw IcaoDocumentRejectedException(IcaoRejection.notGenuine, mrz);
        }
        authenticity = IcaoChipAuthenticity.activeAuthentication;
      } else {
        authenticity = IcaoChipAuthenticity.notSupported;
      }
    }

    IcaoPassiveAuthentication? passive;
    if (verifySignatures) {
      passive = authenticator.verify(sod: sod, dataGroups: groups);
      if (!passive.isValid) {
        throw IcaoDocumentRejectedException(
          IcaoRejection.signature,
          mrz,
          cause: passive.failure,
        );
      }
    }

    progress.finish();
    // Only what was asked for is returned; DG14 and DG15 stay in for a
    // server to check them again.
    final asked = {for (final part in parts) part.dataGroup};
    groups.removeWhere(
      (group, _) =>
          group != IcaoDataGroup.dg1 &&
          group != IcaoDataGroup.dg14 &&
          group != IcaoDataGroup.dg15 &&
          !asked.contains(group),
    );
    final document = IcaoDocument.fromFiles(
      sod: sod,
      dataGroups: groups,
      accessProtocol: protocol,
      cardSecurity: cardSecurity,
      passiveAuthentication: passive,
      authenticity: authenticity,
    );
    return showPrivateData ? document : document.withoutPrivateData();
  }

  // Opens the chip: PACE when it offers it, BAC otherwise or when PACE
  // fails with the MRZ.
  Future<(SecureMessaging, IcaoAccessProtocol, PaceResult?)> _open(
    IcaoAccessKey access,
  ) async {
    final infos = await _cardAccess();
    final info = infos?.preferredPace;
    if (info != null) {
      try {
        final result = await performPace(
          _raw,
          access,
          info,
          infos!.domainParametersOf(info)!,
        );
        _secure = true;
        return (result.session, IcaoAccessProtocol.pace, result);
      } on IcaoAccessException catch (error) {
        if (error.reason == IcaoAccessFailure.wrongKey ||
            access is! IcaoMrzKey) {
          rethrow;
        }
      }
    }
    if (access is! IcaoMrzKey) {
      throw const IcaoAccessException(
        IcaoAccessFailure.unsupported,
        'The chip does not offer PACE: only the MRZ opens it',
      );
    }
    final selected = await _raw.send(
      CommandApdu(0x00, 0xA4, 0x04, 0x0C, data: applicationAid),
    );
    if (!selected.isSuccess) {
      throw IcaoAccessException(
        IcaoAccessFailure.unsupported,
        'No eMRTD application on this chip',
        statusWord: selected.statusWord,
      );
    }
    final session = await performBac(_raw, access);
    _secure = true;
    return (session, IcaoAccessProtocol.bac, null);
  }

  // EF.CardAccess, or null when the chip has none or it cannot be read.
  Future<SecurityInfos?> _cardAccess() async {
    // EF.CardAccess lives in the master file, which a previous read left.
    // A chip that refuses to select it by name is already there.
    await _raw.send(
      CommandApdu(0x00, 0xA4, 0x00, 0x0C, data: const [0x3F, 0x00]),
    );
    try {
      return SecurityInfos.parse(await _readFile(_raw, 0x011C, null));
    } on CardException {
      return null;
    } on FormatException {
      return null;
    }
  }

  // DG14, which the issuing state signed, lists the PACE variants of the
  // chip: a chip that skipped PACE, or Chip Authentication Mapping, when
  // DG14 offers it was made to look older than it is.
  static void _checkDowngrade(
    SecurityInfos? dg14,
    IcaoAccessProtocol protocol,
    PaceResult? pace,
    IcaoMrz mrz,
  ) {
    final listed = dg14?.pace ?? const <PaceInfo>[];
    if (listed.isEmpty) return;
    final String? cause;
    if (protocol == IcaoAccessProtocol.bac) {
      cause = 'BAC was used although DG14 lists PACE';
    } else if (listed.any(
          (info) => info.mapping == PaceMapping.chipAuthentication,
        ) &&
        pace?.info.mapping != PaceMapping.chipAuthentication) {
      cause = 'DG14 lists Chip Authentication Mapping, which was not offered';
    } else {
      cause = null;
    }
    if (cause != null) {
      throw IcaoDocumentRejectedException(
        IcaoRejection.notGenuine,
        mrz,
        cause: cause,
      );
    }
  }

  // Chip Authentication Mapping: the chip's mapping key must be its static
  // key times the secret it sent.
  IcaoChipAuthenticity _checkMapping(
    PaceResult pace,
    Uint8List? cardSecurity,
    IcaoPassiveAuthenticator authenticator,
    IcaoMrz mrz,
  ) {
    final content = cardSecurity == null
        ? null
        : authenticator.verifiedContent(
            _unwrapSignedData(cardSecurity),
            '0.4.0.127.0.7.3.2.1',
          );
    if (content == null) {
      throw IcaoDocumentRejectedException(
        IcaoRejection.notGenuine,
        mrz,
        cause: 'EF.CardSecurity does not verify',
      );
    }
    final keys = SecurityInfos.parse(content).chipAuthenticationKeys;
    final secret = pace.chipAuthenticationData!;
    for (final key in keys) {
      final publicKey = key.publicKey;
      if (publicKey is! EcPublicKey) continue;
      final curve = publicKey.curve;
      final EcPoint expected;
      try {
        expected = curve.decode(pace.chipMappingKey);
      } on FormatException {
        continue;
      }
      final product = curve.multiply(
        unsignedBigInt(secret),
        publicKey.point,
      );
      if (product == expected) {
        return IcaoChipAuthenticity.chipAuthenticationMapping;
      }
    }
    throw IcaoDocumentRejectedException(
      IcaoRejection.notGenuine,
      mrz,
      cause: 'Chip Authentication Mapping does not hold',
    );
  }

  /// Reads a whole file of the chip by its identifier, its size taken from
  /// its first bytes.
  static Future<Uint8List> _readFile(
    CardChannel channel,
    int fileId,
    _Progress? progress,
  ) async {
    await channel.expect(
      CommandApdu(0x00, 0xA4, 0x02, 0x0C, data: [fileId >> 8, fileId & 0xFF]),
      'SELECT FILE ${hexString([fileId >> 8, fileId & 0xFF])}',
    );
    final first = await channel.send(CommandApdu(0x00, 0xB0, 0, 0, le: 8));
    // 6282: the file is shorter than asked for.
    if (!first.isSuccess && first.statusWord != 0x6282) {
      throw CardException('READ BINARY at 0', first.statusWord);
    }
    final head = first.data;
    final size = Tlv.encodedSize(head) ??
        (throw const FormatException('Unreadable file header'));
    if (size > _maxFileSize) throw const FormatException('File too large');
    if (size <= head.length) return Uint8List.fromList(head.sublist(0, size));
    final content = BytesBuilder(copy: false)..add(head);
    progress?.reading(fileId, content.length, size);
    while (content.length < size) {
      final offset = content.length;
      final block = offset > 0x7FFF ? _oddBlock : _block;
      final left = size - offset;
      final chunk = await channel.readBinary(
        offset: offset,
        length: left < block ? left : block,
      );
      if (chunk.isEmpty) throw const FormatException('The file is cut short');
      content.add(chunk);
      progress?.reading(fileId, content.length, size);
    }
    progress?.done(fileId, size);
    return content.takeBytes();
  }

  // Blocks small enough that the protected answer fits a short APDU, with
  // B1's wrapping past 32 KB.
  static const _block = 0xDF;
  static const _oddBlock = 0xD0;
  static const _maxFileSize = 0x100000;

  Future<T> _exclusive<T>(Future<T> Function() action) {
    final result = _last.then((_) => _raw.exclusive(action));
    _last = result.then<void>((_) {}, onError: (Object _) {});
    return result;
  }
}

Set<IcaoDataGroup> _listedGroups(Uint8List sod) {
  final signed = SignedData.parse(_unwrapSignedData(sod));
  return LdsSecurityObject.parse(signed.content).dataGroups.toSet();
}

// EF.SOD wraps its ContentInfo in tag 77; EF.CardSecurity does not.
Uint8List _unwrapSignedData(Uint8List file) {
  final outer = Tlv.parse(file);
  return Uint8List.fromList(outer.tag == 0x77 ? outer.value : outer.encoded);
}

// The content of a data group whose single element is under [tag].
Uint8List _unwrap(Uint8List file, int tag) {
  final outer = Tlv.parse(file);
  if (outer.tag != tag) throw const FormatException('Unexpected file tag');
  return Uint8List.fromList(outer.value);
}

/// Estimates read progress from the usual size of each file planned, then
/// from its real size once known.
final class _Progress {
  _Progress(this._report, this._planned);

  static const access = -1;
  static const chipCheck = -2;

  final IcaoReadProgress? _report;
  final Map<int, int> _planned;
  final _sizes = <int, int>{};
  final _read = <int, int>{};
  double _last = 0;

  void step(int key) => reading(key, _planned[key] ?? 0, _planned[key] ?? 0);

  void reading(int fileId, int bytes, int size) {
    _sizes[fileId] = size;
    _read[fileId] = bytes;
    _emit();
  }

  void done(int fileId, int size) => reading(fileId, size, size);

  void finish() {
    final report = _report;
    if (report != null && _last < 1) report(_last = 1);
  }

  void _emit() {
    final report = _report;
    if (report == null) return;
    // Files not met yet count with their usual size, so the bar does not
    // run ahead of DG2; an absent one simply never counts.
    var total = 0;
    var done = 0;
    for (final key in {..._planned.keys, ..._sizes.keys}) {
      total += _sizes[key] ?? _planned[key]!;
      done += _read[key] ?? 0;
    }
    if (total == 0) return;
    final fraction = (done / total).clamp(0.0, 0.99);
    if (fraction <= _last) return;
    report(_last = fraction);
  }
}
