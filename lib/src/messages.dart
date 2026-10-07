import 'package:eid/eid.dart';
import 'package:eid_icao/src/document.dart';
import 'package:eid_icao/src/exceptions.dart';
import 'package:eid_icao/src/watcher.dart';

/// The languages of the messages: French, Dutch, German and English.
enum IcaoLanguage {
  /// French.
  fr,

  /// Dutch.
  nl,

  /// German.
  de,

  /// English.
  en,
}

/// A sentence to show the user for [error], in [language]: whatever an
/// `IcaoChipReadFailed` carries.
///
/// ```dart
/// case IcaoChipReadFailed failed:
///   showError(icaoErrorMessage(failed.error, IcaoLanguage.fr));
/// ```
String icaoErrorMessage(Exception error, IcaoLanguage language) {
  String say(String fr, String nl, String de, String en) =>
      [fr, nl, de, en][language.index];

  switch (error) {
    case IcaoDocumentRejectedException(:final reason, :final mrz):
      switch (reason) {
        case IcaoRejection.expired:
          final expiry = mrz.expiryDate;
          final day = expiry == null
              ? ''
              : ' ${_two(expiry.day)}/${_two(expiry.month)}/${expiry.year}';
          return say(
            'Document expiré$day',
            'Document vervallen$day',
            'Dokument abgelaufen$day',
            'Document expired$day',
          );
        case IcaoRejection.documentType:
          return say(
            "Ce type de document n'est pas accepté",
            'Dit type document wordt niet aanvaard',
            'Dieser Dokumenttyp wird nicht akzeptiert',
            'This type of document is not accepted',
          );
        case IcaoRejection.signature:
          return say(
            "Les données de la puce ne sont pas signées par l'État émetteur",
            'De gegevens op de chip zijn niet ondertekend door de uitgevende '
                'staat',
            'Die Chipdaten sind nicht vom ausstellenden Staat signiert',
            "The chip's data is not signed by the issuing state",
          );
        case IcaoRejection.notGenuine:
          return say(
            "La puce n'a pas pu prouver qu'elle est authentique",
            'De chip kon niet bewijzen dat hij echt is',
            'Der Chip konnte seine Echtheit nicht nachweisen',
            'The chip could not prove it is genuine',
          );
      }
    case IcaoAccessException(reason: IcaoAccessFailure.wrongKey):
      return say(
        'Le CAN ou les données de la MRZ ne correspondent pas à ce document',
        'De CAN of de MRZ-gegevens komen niet overeen met dit document',
        'CAN oder MRZ-Daten passen nicht zu diesem Dokument',
        'The CAN or MRZ data does not match this document',
      );
    case IcaoAccessException(reason: IcaoAccessFailure.unsupported):
      return say(
        "Cette puce ne s'ouvre qu'avec les données de la MRZ",
        'Deze chip opent alleen met de MRZ-gegevens',
        'Dieser Chip lässt sich nur mit den MRZ-Daten öffnen',
        'This chip opens with the MRZ data only',
      );
    case IcaoAccessCancelledException():
      return say(
        "Ni CAN ni MRZ n'a été saisi",
        'Er werd geen CAN of MRZ ingevoerd',
        'Weder CAN noch MRZ wurde eingegeben',
        'No CAN or MRZ was given',
      );
    case IcaoAccessException() || IcaoSecureMessagingException():
      return say(
        'La communication sécurisée avec la puce a échoué',
        'De beveiligde verbinding met de chip is mislukt',
        'Die gesicherte Verbindung zum Chip ist fehlgeschlagen',
        'Secure communication with the chip failed',
      );
    case CardTransportException():
      return say(
        'Le document ne répond pas : est-il bien posé sur le lecteur ?',
        'Het document antwoordt niet: ligt het goed op de lezer?',
        'Das Dokument antwortet nicht: liegt es richtig auf dem Leser?',
        'The document does not answer: is it on the reader?',
      );
    case FormatException():
      return say(
        'La puce contient des données inattendues',
        'De chip bevat onverwachte gegevens',
        'Der Chip enthält unerwartete Daten',
        'The chip holds unexpected data',
      );
    default:
      return say(
        'La puce a refusé la lecture',
        'De chip weigerde het lezen',
        'Der Chip hat das Lesen verweigert',
        'The chip refused to be read',
      );
  }
}

String _two(int value) => value.toString().padLeft(2, '0');
