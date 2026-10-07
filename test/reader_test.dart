import 'dart:convert';
import 'dart:typed_data';

import 'package:eid_icao/eid_icao.dart';
import 'package:eid_icao/testing.dart';
import 'package:test/test.dart';

import 'openssl_pki.dart';

Matcher _rejectedFor(IcaoRejection reason) => throwsA(
      isA<IcaoDocumentRejectedException>()
          .having((e) => e.reason, 'reason', reason),
    );

Matcher _accessFailing(IcaoAccessFailure reason) => throwsA(
      isA<IcaoAccessException>().having((e) => e.reason, 'reason', reason),
    );

/// A chip with some of its answers rewritten, as a forgery would.
final class _Forgery implements CardTransport {
  _Forgery(this.chip, this.rewrite);

  final SimulatedIcaoChip chip;
  final Uint8List? Function(Uint8List command) rewrite;

  @override
  Future<Uint8List> transmit(Uint8List command) async =>
      rewrite(command) ?? await chip.transmit(command);
}

void main() {
  group('IcaoReader', () {
    test('reads a passport with its CAN', () async {
      final chip = SimulatedIcaoChip();
      final progress = <double>[];
      final document = await IcaoReader(chip).read(
        access: chip.canKey,
        onProgress: progress.add,
      );

      final mrz = document.mrz;
      expect(mrz.documentType, IcaoDocumentType.passport);
      expect(mrz.lastName, 'SPECIMEN');
      expect(mrz.firstNames, 'ALICE MARIE');
      expect(mrz.documentNumber, 'UT1234567');
      expect(mrz.birthDate, PartialDate(1990, 5, 15));
      expect(mrz.sex, Sex.female);
      expect(mrz.isValid, isTrue);

      expect(document.accessProtocol, IcaoAccessProtocol.pace);
      expect(document.face?.format, IcaoImageFormat.jpeg);
      expect(document.face?.bytes, specimenPhoto);
      expect(document.face?.width, 200);
      expect(document.faces.single.encoding, IcaoFaceEncoding.iso19794);
      expect(document.personalDetails?.lastName, 'SPECIMEN');
      expect(document.personalDetails?.firstNames, 'ALICE MARIE');
      expect(document.personalDetails?.birthDate, PartialDate(1990, 5, 15));
      expect(document.personalDetails?.birthPlace, ['ZENITH', 'UTOPIA']);
      expect(
        document.documentDetails?.issuingAuthority,
        'MINISTRY OF FOREIGN AFFAIRS',
      );
      expect(document.documentDetails?.issueDate, PartialDate(2024, 3, 14));
      expect(document.decodingFailures, isEmpty);

      expect(document.signaturesVerified, isTrue);
      expect(document.passiveAuthentication?.chain, IcaoChainStatus.verified);
      expect(document.authenticity, IcaoChipAuthenticity.chipAuthentication);

      expect(progress.last, 1);
      for (var i = 1; i < progress.length; i++) {
        expect(progress[i], greaterThan(progress[i - 1]));
      }
    });

    test('opens PACE with the MRZ too', () async {
      final chip = SimulatedIcaoChip();
      final document = await IcaoReader(chip).read(access: chip.mrzKey);
      expect(document.accessProtocol, IcaoAccessProtocol.pace);
    });

    test('reads a first generation passport with BAC', () async {
      final chip = SimulatedIcaoChip(
        access: SimulatedChipAccess.bacOnly,
        proof: SimulatedChipProof.activeAuthenticationRsa,
      );
      final reader = IcaoReader(chip);
      expect(await reader.acceptsCan(), isFalse);
      final document = await reader.read(access: chip.mrzKey);
      expect(document.accessProtocol, IcaoAccessProtocol.bac);
      expect(document.authenticity, IcaoChipAuthenticity.activeAuthentication);
      await expectLater(
        reader.read(access: chip.canKey),
        _accessFailing(IcaoAccessFailure.unsupported),
      );
    });

    test('reads a PACE-only identity card, TD1', () async {
      final chip = SimulatedIcaoChip(
        type: IcaoDocumentType.identityCard,
        documentNumber: '592123456789',
        access: SimulatedChipAccess.paceOnly,
        proof: SimulatedChipProof.chipAuthenticationMapping,
      );
      final reader = IcaoReader(chip);
      expect(await reader.acceptsCan(), isTrue);
      final document = await reader.read(access: chip.canKey);
      expect(document.mrz.format, IcaoMrzFormat.td1);
      expect(document.mrz.documentNumber, '592123456789');
      expect(document.mrz.isValid, isTrue);
      expect(
        document.authenticity,
        IcaoChipAuthenticity.chipAuthenticationMapping,
      );
      expect(document.cardSecurity, isNotNull);
      final byMrz = await reader.read(access: chip.mrzKey);
      expect(byMrz.mrz.lastName, 'SPECIMEN');
    });

    test('reports a wrong CAN and a wrong MRZ', () async {
      final chip = SimulatedIcaoChip();
      await expectLater(
        IcaoReader(chip).read(access: IcaoAccessKey.can('000000')),
        _accessFailing(IcaoAccessFailure.wrongKey),
      );
      final old = SimulatedIcaoChip(access: SimulatedChipAccess.bacOnly);
      await expectLater(
        IcaoReader(old).read(
          access: IcaoAccessKey.mrz(
            documentNumber: 'UT1234567',
            birthDate: PartialDate(1990, 5, 16),
            expiryDate: DateTime.utc(2034, 3, 13),
          ),
        ),
        _accessFailing(IcaoAccessFailure.wrongKey),
      );
    });

    for (final proof in SimulatedChipProof.values) {
      test('turns down a cloned chip proving itself by ${proof.name}',
          () async {
        final genuine = SimulatedIcaoChip(proof: proof);
        final document = await IcaoReader(genuine).read(access: genuine.canKey);
        expect(
          document.authenticity,
          switch (proof) {
            SimulatedChipProof.chipAuthentication =>
              IcaoChipAuthenticity.chipAuthentication,
            SimulatedChipProof.chipAuthenticationMapping =>
              IcaoChipAuthenticity.chipAuthenticationMapping,
            SimulatedChipProof.activeAuthenticationEc ||
            SimulatedChipProof.activeAuthenticationRsa =>
              IcaoChipAuthenticity.activeAuthentication,
            SimulatedChipProof.none => IcaoChipAuthenticity.notSupported,
          },
        );
        if (proof == SimulatedChipProof.none) return;
        final clone = SimulatedIcaoChip(proof: proof, cloned: true);
        await expectLater(
          IcaoReader(clone).read(access: clone.canKey),
          _rejectedFor(IcaoRejection.notGenuine),
        );
        final unchecked = await IcaoReader(clone).read(
          access: clone.canKey,
          verifyCard: false,
        );
        expect(unchecked.authenticity, isNull);
      });
    }

    test(
        'turns down a clone answering bare successes after Chip '
        'Authentication', () async {
      final chip = SimulatedIcaoChip();
      var authenticated = false;
      final forgery = _Forgery(chip, (command) {
        if (authenticated) return Uint8List.fromList(const [0x90, 0x00]);
        // The protected GENERAL AUTHENTICATE of Chip Authentication.
        if (command[0] == 0x0C && command[1] == 0x86) authenticated = true;
        return null;
      });
      await expectLater(
        IcaoReader(forgery).read(
          access: chip.canKey,
          parts: const {},
          trustedRoots: [chip.simulatedCsca],
        ),
        _rejectedFor(IcaoRejection.notGenuine),
      );
    });

    test('turns down a chip hiding PACE to be read with BAC', () async {
      final chip = SimulatedIcaoChip();
      final forgery = _Forgery(
        chip,
        (command) => hexString(command) == '00A4020C02011C'
            ? Uint8List.fromList(const [0x6A, 0x82])
            : null,
      );
      await expectLater(
        IcaoReader(forgery).read(
          access: chip.mrzKey,
          trustedRoots: [chip.simulatedCsca],
        ),
        throwsA(
          isA<IcaoDocumentRejectedException>()
              .having((e) => e.reason, 'reason', IcaoRejection.notGenuine)
              .having((e) => e.cause, 'cause', contains('BAC')),
        ),
      );
    });

    test('turns down a data group changed after signing', () async {
      final chip = SimulatedIcaoChip(tamperedGroup: IcaoDataGroup.dg2);
      await expectLater(
        IcaoReader(chip).read(access: chip.canKey),
        _rejectedFor(IcaoRejection.signature),
      );
      final unchecked = await IcaoReader(chip).read(
        access: chip.canKey,
        verifySignatures: false,
      );
      expect(unchecked.passiveAuthentication, isNull);
      expect(unchecked.authenticity, isNull);
    });

    test('turns down a document no trusted CSCA signed', () async {
      final chip = SimulatedIcaoChip();
      await expectLater(
        IcaoReader(chip).read(
          access: chip.canKey,
          trustedRoots: [IcaoCertificate.parse(cscaEc)],
        ),
        _rejectedFor(IcaoRejection.signature),
      );
    });

    test('turns down an expired document unless accepted', () async {
      final chip = SimulatedIcaoChip(expiryDate: DateTime.utc(2020, 1, 31));
      await expectLater(
        IcaoReader(chip).read(access: chip.canKey),
        _rejectedFor(IcaoRejection.expired),
      );
      final document = await IcaoReader(chip).read(
        access: chip.canKey,
        acceptExpired: true,
      );
      expect(document.mrz.expiryDate, DateTime.utc(2020, 1, 31));
    });

    test('turns down the document types not accepted', () async {
      final card = SimulatedIcaoChip(type: IcaoDocumentType.identityCard);
      await expectLater(
        IcaoReader(card).read(
          access: card.canKey,
          acceptedTypes: {IcaoDocumentType.passport},
        ),
        _rejectedFor(IcaoRejection.documentType),
      );
    });

    test('reads only the parts asked for', () async {
      final chip = SimulatedIcaoChip();
      final apdus = <ApduExchange>[];
      final document = await IcaoReader(chip, onApdu: apdus.add).read(
        access: chip.canKey,
        parts: const {},
      );
      expect(document.face, isNull);
      expect(document.personalDetails, isNull);
      // DG1 is read, but left out with the private data.
      expect(document.dataGroups.keys, [IcaoDataGroup.dg14]);
      expect(
        apdus.where((e) => hexString(e.command).startsWith('00A4020C020102')),
        isEmpty,
      );
    });

    group('showPrivateData', () {
      const number = '90051512391';

      test('leaves the personal numbers out by default', () async {
        for (final type in [
          IcaoDocumentType.passport,
          IcaoDocumentType.identityCard,
        ]) {
          final chip = SimulatedIcaoChip(
            type: type,
            documentNumber:
                type == IcaoDocumentType.identityCard ? '592123456789' : null,
            personalNumber: number,
          );
          final apdus = <ApduExchange>[];
          final document = await IcaoReader(chip, onApdu: apdus.add)
              .read(access: chip.canKey);
          expect(document.signaturesVerified, isTrue);
          expect(document.mrz.optionalData, '');
          expect(document.mrz.optionalData2, '');
          expect(document.mrz.text, isNot(contains(number)));
          expect(document.mrz.documentNumber, chip.documentNumber);
          expect(document.mrz.isValid, isTrue);
          expect(document.personalDetails?.personalNumber, isNull);
          expect(document.personalDetails?.lastName, 'SPECIMEN');
          expect(document.dataGroups, isNot(contains(IcaoDataGroup.dg1)));
          expect(document.dataGroups, isNot(contains(IcaoDataGroup.dg11)));
          expect(jsonEncode(document.toJson()), isNot(contains(number)));
          final hex = hexString(utf8.encode(number));
          expect(apdus.map((e) => '$e'), everyElement(isNot(contains(hex))));
          expect(
            IcaoDocument.fromJson(document.toJson()).mrz.text,
            document.mrz.text,
          );
        }
      });

      test('shows them when asked', () async {
        final chip = SimulatedIcaoChip(
          type: IcaoDocumentType.identityCard,
          personalNumber: number,
        );
        final document = await IcaoReader(chip).read(
          access: chip.canKey,
          showPrivateData: true,
        );
        expect(document.mrz.optionalData2, number);
        expect(document.personalDetails?.personalNumber, number);
        expect(document.dataGroups, contains(IcaoDataGroup.dg1));
      });
    });

    test('reads a face in ISO/IEC 39794-5', () async {
      final chip = SimulatedIcaoChip(faceEncoding: IcaoFaceEncoding.iso39794);
      final document = await IcaoReader(chip).read(access: chip.canKey);
      expect(document.faces.single.encoding, IcaoFaceEncoding.iso39794);
      expect(document.face?.bytes, specimenPhoto);
      expect(document.face?.height, 260);
    });

    test('reads a face larger than 32 KB with READ BINARY B1', () async {
      final photo = Uint8List(40000)..setAll(0, const [0xFF, 0xD8, 0xFF]);
      final chip = SimulatedIcaoChip(photo: photo);
      final apdus = <ApduExchange>[];
      final document = await IcaoReader(chip, onApdu: apdus.add)
          .read(access: chip.canKey, parts: {IcaoPart.face});
      expect(document.face?.bytes, photo);
      expect(apdus.where((e) => e.command[1] == 0xB1), isNotEmpty);
    });

    test('reports commands as sent before protection', () async {
      final chip = SimulatedIcaoChip();
      final apdus = <ApduExchange>[];
      await IcaoReader(chip, onApdu: apdus.add).read(access: chip.canKey);
      final commands = apdus.map((e) => hexString(e.command)).toList();
      expect(commands, contains('00A4020C020101'));
      expect(commands.where((c) => c.startsWith('0C')), isEmpty);
    });

    test('round-trips through JSON for a server to verify', () async {
      final chip = SimulatedIcaoChip();
      final document = await IcaoReader(chip).read(access: chip.canKey);
      final copy = IcaoDocument.fromJson(document.toJson());
      expect(copy.mrz.text, document.mrz.text);
      expect(copy.face?.bytes, document.face?.bytes);
      expect(copy.accessProtocol, IcaoAccessProtocol.pace);
      expect(copy.signaturesVerified, isFalse);
      final check = IcaoPassiveAuthenticator(
        trustedRoots: [chip.simulatedCsca],
      ).verify(sod: copy.sod, dataGroups: copy.dataGroups);
      expect(check.isValid, isTrue);
      expect(check.verifiedGroups, copy.dataGroups.keys.toSet());
    });

    test('fails when the chip leaves mid-read', () async {
      final chip = SimulatedIcaoChip();
      final reading = IcaoReader(chip).read(
        access: chip.canKey,
        onProgress: (fraction) {
          if (fraction > 0.5) chip.remove();
        },
      );
      await expectLater(reading, throwsA(isA<CardTransportException>()));
    });
  });

  group('IcaoWatcher', () {
    test('reads a document put on the reader, probes kept out', () async {
      final chip = SimulatedIcaoChip(latency: const Duration(milliseconds: 2))
        ..remove();
      final watcher = IcaoWatcher(
        chip,
        accessKey: chip.canKey,
        interval: const Duration(milliseconds: 5),
      )..start();
      final events = <IcaoEvent>[];
      watcher.events.listen(events.add);

      chip.insert();
      final read = await watcher.events
          .firstWhere((event) => event is IcaoChipRead) as IcaoChipRead;
      expect(
        read.document.authenticity,
        IcaoChipAuthenticity.chipAuthentication,
      );
      expect(events.first, isA<IcaoChipInserted>());
      expect(watcher.document, same(read.document));

      chip.remove();
      await watcher.events.firstWhere((event) => event is IcaoChipRemoved);
      expect(watcher.document, isNull);
      await watcher.dispose();
    });

    test('asks again for a refused key, then reads', () async {
      final chip = SimulatedIcaoChip();
      final requests = <IcaoAccessRequest>[];
      final keys = [IcaoAccessKey.can('111111'), chip.canKey];
      final watcher = IcaoWatcher(
        chip,
        accessPrompt: (request) async {
          requests.add(request);
          return keys.removeAt(0);
        },
        interval: const Duration(milliseconds: 5),
      )..start();

      await watcher.events.firstWhere((event) => event is IcaoChipRead);
      expect(requests, hasLength(2));
      expect(requests.first.acceptsCan, isTrue);
      expect(requests.first.refused, isNull);
      expect(requests.last.refused?.reason, IcaoAccessFailure.wrongKey);
      await watcher.dispose();
    });

    test('reports a prompt given up on', () async {
      final chip = SimulatedIcaoChip();
      final watcher = IcaoWatcher(
        chip,
        accessPrompt: (_) async => null,
        interval: const Duration(milliseconds: 5),
      )..start();
      final failed = await watcher.events
              .firstWhere((event) => event is IcaoChipReadFailed)
          as IcaoChipReadFailed;
      expect(failed.error, isA<IcaoAccessCancelledException>());
      expect(
        icaoErrorMessage(failed.error, IcaoLanguage.fr),
        "Ni CAN ni MRZ n'a été saisi",
      );
      await watcher.dispose();
    });
  });

  test('words every failure in four languages', () {
    final mrz = IcaoMrz.parse(
      'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<\n'
      'L898902C36UTO7408122F1204159ZE184226B<<<<<10',
    );
    final errors = <Exception>[
      for (final reason in IcaoRejection.values)
        IcaoDocumentRejectedException(reason, mrz),
      for (final reason in IcaoAccessFailure.values)
        IcaoAccessException(reason, 'test'),
      const IcaoAccessCancelledException(),
      const IcaoSecureMessagingException('test'),
      const CardTransportException('test'),
      const FormatException('test'),
      const CardException('READ BINARY', 0x6982),
    ];
    for (final language in IcaoLanguage.values) {
      final messages = errors.map((e) => icaoErrorMessage(e, language));
      expect(messages.every((m) => m.isNotEmpty), isTrue);
    }
    expect(
      icaoErrorMessage(errors.first, IcaoLanguage.en),
      'Document expired 15/04/2012',
    );
  });
}
