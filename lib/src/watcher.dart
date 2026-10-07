import 'dart:async';

import 'package:eid/eid.dart';
import 'package:eid_icao/src/access_key.dart';
import 'package:eid_icao/src/certificate.dart';
import 'package:eid_icao/src/document.dart';
import 'package:eid_icao/src/exceptions.dart';
import 'package:eid_icao/src/mrz.dart';
import 'package:eid_icao/src/reader.dart';
import 'package:eid_icao/src/simulated_transport.dart';

/// What the chip asks for before it is read.
final class IcaoAccessRequest {
  /// A request for the chip [reader] reads.
  const IcaoAccessRequest({
    required this.reader,
    required this.acceptsCan,
    this.refused,
  });

  /// The reader of the chip.
  final IcaoReader reader;

  /// Whether the CAN opens this chip; otherwise only the MRZ does.
  final bool acceptsCan;

  /// Why the previous key was turned down, null on the first ask.
  final IcaoAccessException? refused;
}

/// Asks for the MRZ or CAN of the document on the reader, or returns null
/// when the user gives up.
typedef IcaoAccessPrompt = Future<IcaoAccessKey?> Function(
  IcaoAccessRequest request,
);

/// The user gave no key: the [IcaoAccessPrompt] returned null.
final class IcaoAccessCancelledException implements Exception {
  /// The user gave up.
  const IcaoAccessCancelledException();

  @override
  String toString() => 'IcaoAccessCancelledException: no key was given';
}

/// Something that happened to a document on a watched reader.
sealed class IcaoEvent {
  const IcaoEvent();
}

/// A document was put on the reader.
final class IcaoChipInserted extends IcaoEvent {
  /// A chip [reader] reads.
  const IcaoChipInserted(this.reader);

  /// The reader of the chip, valid while it stays.
  final IcaoReader reader;
}

/// A document was read.
final class IcaoChipRead extends IcaoEvent {
  /// [reader] read [document].
  const IcaoChipRead(this.document, this.reader);

  /// What was read.
  final IcaoDocument document;

  /// The reader of the chip.
  final IcaoReader reader;
}

/// A read failed.
///
/// A document taken away mid-read is reported here first, with a
/// `CardTransportException`, then by [IcaoChipRemoved].
final class IcaoChipReadFailed extends IcaoEvent {
  /// A read that failed with [error].
  const IcaoChipReadFailed(this.error);

  /// An `IcaoDocumentRejectedException`, an `IcaoAccessException`, an
  /// `IcaoAccessCancelledException`, an `IcaoSecureMessagingException`, a
  /// `CardException`, a `CardTransportException` or a `FormatException`.
  final Exception error;
}

/// The document left the reader and what was read from it is forgotten.
final class IcaoChipRemoved extends IcaoEvent {
  /// The document left.
  const IcaoChipRemoved();
}

/// Watches a reader for passports and identity cards and, when [autoRead]
/// is on, reads each one as it is put down.
///
/// The chip opens only with its MRZ or CAN: give [accessKey] when it is
/// known, or [accessPrompt] to ask the user.
///
/// ```dart
/// final watcher = IcaoWatcher(
///   CcidTerminal.any(),
///   accessPrompt: (request) => askUserForCan(request.refused),
/// )..start();
/// watcher.events.listen((event) {
///   if (event case IcaoChipRead(:final document)) show(document);
/// });
/// ```
///
/// Options can be changed at any time and apply to the next read.
final class IcaoWatcher {
  /// A watcher of [terminal], polled every [interval] once [start]ed.
  IcaoWatcher(
    CardTerminal terminal, {
    this.accessKey,
    this.accessPrompt,
    this.autoRead = true,
    Set<IcaoPart> parts = IcaoPart.all,
    this.acceptExpired = false,
    this.acceptedTypes,
    this.verifySignatures = true,
    this.trustedRoots,
    this.verifyCard = true,
    this.showPrivateData = false,
    this.onApdu,
    this.onProgress,
    Duration interval = const Duration(milliseconds: 400),
  })  : parts = {...parts},
        _cards = CardWatcher(terminal, interval: interval);

  /// The key of the documents read, when known, such as a CAN typed in
  /// before putting the card down. Tried before [accessPrompt].
  IcaoAccessKey? accessKey;

  /// Asks for a key when there is no [accessKey], or when the chip refused
  /// one, until the chip opens or the user gives up.
  ///
  /// Close a prompt still open on [IcaoChipRemoved]; its answer is lost.
  IcaoAccessPrompt? accessPrompt;

  /// Whether a document is read as soon as it is put down.
  bool autoRead;

  /// What reads bring back besides the MRZ.
  Set<IcaoPart> parts;

  /// Whether an expired document is read rather than rejected.
  bool acceptExpired;

  /// The document types read, or null for all; others are rejected.
  Set<IcaoDocumentType>? acceptedTypes;

  /// Whether Passive Authentication runs.
  bool verifySignatures;

  /// The CSCAs to trust, or null to leave the chain unverified (and, for a
  /// `SimulatedIcaoChip`, to trust its own CSCA).
  Iterable<IcaoCertificate>? trustedRoots;

  /// Whether the chip must prove it is genuine.
  bool verifyCard;

  /// Whether the personal numbers are read, off by default: see
  /// `IcaoReader.read`.
  bool showPrivateData;

  /// Called with each command and answer, except presence checks.
  ApduListener? onApdu;

  /// Follows each read, from 0 to 1.
  IcaoReadProgress? onProgress;

  final CardWatcher _cards;
  final _events = StreamController<IcaoEvent>.broadcast();
  StreamSubscription<CardEvent>? _subscription;
  Timer? _autoReading;
  IcaoReader? _reader;
  IcaoDocument? _document;
  Future<IcaoDocument>? _reading;
  IcaoReader? _readingReader;

  /// The terminal watched.
  CardTerminal get terminal => _cards.terminal;

  /// What happens to documents. A failure to reach the terminal is an
  /// error.
  Stream<IcaoEvent> get events => _events.stream;

  /// The reader of the chip on the terminal, or null when there is none.
  IcaoReader? get reader => _reader;

  /// What was last read from the chip on the terminal, or null.
  IcaoDocument? get document => _document;

  /// Whether a document is on the terminal.
  bool get hasChip => _reader != null;

  /// Starts watching. A document already there is reported.
  void start() {
    _subscription ??= _cards.events.listen(
      _onCard,
      onError: _events.addError,
    );
    _cards.start();
  }

  /// Stops watching and releases the chip.
  Future<void> stop() async {
    _autoReading?.cancel();
    final reader = _reader;
    await _cards.stop();
    // A start() meanwhile may already have reported a new chip.
    if (identical(_reader, reader)) _release();
  }

  /// Stops watching for good and closes [events].
  Future<void> dispose() async {
    _autoReading?.cancel();
    final stopping = _cards.dispose();
    // Not awaited: its future would never complete under a fake clock.
    unawaited(_subscription?.cancel());
    _subscription = null;
    await stopping;
    _release();
    await _events.close();
  }

  /// Reads the chip on the terminal and reports the outcome on [events].
  ///
  /// Throws a [CardTransportException] when there is none, and whatever
  /// [IcaoChipReadFailed] carries when the read fails.
  Future<IcaoDocument> read() {
    final reader = _reader;
    if (reader == null) {
      return Future.error(
        const CardTransportException('No document on the terminal'),
      );
    }
    // A read under way for this chip is shared, prompt included.
    final current = _reading;
    if (current != null && identical(_readingReader, reader)) return current;
    final reading = _reading = _read(reader);
    _readingReader = reader;
    void done() {
      if (identical(_reading, reading)) _reading = _readingReader = null;
    }

    reading.then((_) => done(), onError: (Object _) => done());
    return reading;
  }

  Future<IcaoDocument> _read(IcaoReader reader) async {
    try {
      var key = accessKey;
      IcaoAccessException? refused;
      bool? acceptsCan;
      while (true) {
        if (key == null) {
          final prompt = accessPrompt;
          if (prompt == null) throw const IcaoAccessCancelledException();
          acceptsCan ??= await reader.acceptsCan();
          key = await prompt(IcaoAccessRequest(
            reader: reader,
            acceptsCan: acceptsCan,
            refused: refused,
          ));
          if (key == null) throw const IcaoAccessCancelledException();
          if (!identical(reader, _reader)) {
            throw const CardTransportException('The document was removed');
          }
        }
        try {
          final document = await reader.read(
            access: key,
            parts: parts,
            acceptExpired: acceptExpired,
            acceptedTypes: acceptedTypes,
            verifySignatures: verifySignatures,
            trustedRoots: trustedRoots ??
                switch (terminal) {
                  // The simulated chip's CSCA, for the simulated chip alone.
                  final SimulatedTransport simulated => [
                      simulated.simulatedCsca,
                    ],
                  _ => null,
                },
            verifyCard: verifyCard,
            showPrivateData: showPrivateData,
            onProgress: onProgress,
          );
          if (identical(reader, _reader)) {
            _document = document;
            _events.add(IcaoChipRead(document, reader));
          }
          return document;
        } on IcaoAccessException catch (error) {
          // A refused key is asked again; a protocol failure is not.
          if (accessPrompt == null ||
              error.reason == IcaoAccessFailure.protocolError) {
            rethrow;
          }
          refused = error;
          key = null;
        }
      }
    } on Exception catch (error) {
      if (identical(reader, _reader)) _events.add(IcaoChipReadFailed(error));
      rethrow;
    }
  }

  void _onCard(CardEvent event) {
    switch (event) {
      case CardInserted(:final connection):
        final reader = _reader = IcaoReader(
          connection,
          onApdu: (exchange) => onApdu?.call(exchange),
        );
        _document = null;
        _events.add(IcaoChipInserted(reader));
        // Deferred so that listeners hear of the insertion first.
        if (autoRead) _autoReading = Timer(Duration.zero, _autoRead);
      case CardRemoved():
        _forget();
        _events.add(const IcaoChipRemoved());
    }
  }

  Future<void> _autoRead() async {
    try {
      await read();
    } on Exception {
      // Already reported on the stream.
    } on Object catch (error, stackTrace) {
      if (!_events.isClosed) _events.addError(error, stackTrace);
    }
  }

  // Stopping lets go of the chip: listeners hear it as a removal.
  void _release() {
    final hadChip = _reader != null;
    _forget();
    if (hadChip && !_events.isClosed) _events.add(const IcaoChipRemoved());
  }

  void _forget() {
    _reader = null;
    _document = null;
  }
}
