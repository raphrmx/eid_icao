/// Why the chip could not be opened.
enum IcaoAccessFailure {
  /// The chip refused the MRZ or CAN: a typo, or another document's key.
  wrongKey,

  /// The key does not fit the chip: a CAN on a chip without PACE, or a
  /// chip offering no protocol this package supports.
  unsupported,

  /// The chip answered the protocol in an unexpected way.
  protocolError,
}

/// The chip could not be opened with the key given.
final class IcaoAccessException implements Exception {
  /// A failure for [reason], described by [message].
  const IcaoAccessException(this.reason, this.message, {this.statusWord});

  /// Why access failed.
  final IcaoAccessFailure reason;

  /// What happened, such as `PACE mutual authentication failed`.
  final String message;

  /// The status word the chip returned, when it refused a command.
  final int? statusWord;

  @override
  String toString() {
    final status = statusWord == null
        ? ''
        : ' (${statusWord!.toRadixString(16).padLeft(4, '0').toUpperCase()})';
    return 'IcaoAccessException: $message$status';
  }
}

/// Secure messaging with the chip broke: an answer failed its MAC check or
/// lacked its protection.
final class IcaoSecureMessagingException implements Exception {
  /// A failure described by [message].
  const IcaoSecureMessagingException(this.message);

  /// What went wrong.
  final String message;

  @override
  String toString() => 'IcaoSecureMessagingException: $message';
}
