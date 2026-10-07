# eid_icao

[![Pub Version](https://img.shields.io/pub/v/eid_icao?color=0175C2)](https://pub.dev/packages/eid_icao)
[![Build](https://img.shields.io/github/actions/workflow/status/raphrmx/eid_icao/ci.yml?branch=main&label=build)](https://github.com/raphrmx/eid_icao/actions/workflows/ci.yml)
![Maintainer](https://img.shields.io/badge/Maintainer-Raphael_Vrient-733d90)
[![Licence](https://img.shields.io/badge/Licence-MIT-8C6A3F)](LICENSE)
![Platforms](https://img.shields.io/badge/Platforms-Android,_iOS,_macOS,_Windows,_Linux-22375C.svg)
[![Donate with PayPal](https://img.shields.io/badge/Donate-PayPal-00457C?logo=paypal&logoColor=white)](https://www.paypal.com/donate/?hosted_button_id=ZN6D382YQAV5N)

Reads the contactless chip of passports and identity cards, ICAO 9303:
passports worldwide, and the identity cards of the European Union issued
since August 2021, which Regulation (EU) 2019/1157 requires to carry it. In
pure Dart, over any `eid` transport.

- Opens the chip with BAC or PACE, from the MRZ or the card access number
  (CAN), then talks to it under secure messaging.
- Reads the MRZ (DG1), the face (DG2, ISO/IEC 19794-5 or 39794-5), the
  displayed signature (DG7), the additional personal and document details
  (DG11, DG12) and the persons to notify (DG16).
- Checks that the issuing state signed the data (Passive Authentication)
  and that the chip is not a copy (Chip Authentication, Chip Authentication
  Mapping or Active Authentication).
- Gives the photo as JPEG or PNG, ready to show: JPEG 2000, which most
  identity cards use, is decoded in pure Dart.

Reading a document takes a transport: `eid_nfc` for the NFC of an Android
phone or an iPhone, `eid_ccid` for a contactless PC/SC reader on Android,
iOS, macOS, Windows and Linux. No browser lets a page talk to an identity
chip: on the web, the package checks documents read elsewhere
(`IcaoDocument.fromJson`, `IcaoPassiveAuthenticator`) and runs the
simulator.

![Which packages for which document: a Belgian card in a USB reader takes eid_belgium and eid_ccid and needs no key; a passport or an EU identity card takes eid_icao, with eid_nfc on a phone or eid_ccid on a contactless USB reader, and needs the CAN or the MRZ](https://public.comapps.be/packages/eid/eid_situations.svg)

## Install

```yaml
dependencies:
  eid_icao: ^0.1.0
  eid_ccid: ^0.1.0 # a contactless PC/SC reader, in a Flutter application
```

## Read a document

```dart
import 'package:eid_ccid/eid_ccid.dart';
import 'package:eid_icao/eid_icao.dart';

final readers = await CcidTransport.listReaders();
final transport = await CcidTransport.connect(readers.first);

final document = await IcaoReader(transport).read(
  access: IcaoAccessKey.can('123456'),
);
document.mrz.lastName;      // SPECIMEN
document.mrz.birthDate;     // 1990-05-15
document.photo;             // JPEG or PNG, for Image.memory
document.authenticity;      // chipAuthentication

await transport.disconnect();
```

The chip opens only with a key printed on the document:

```dart
IcaoAccessKey.can('123456');                // on EU identity cards
IcaoAccessKey.mrz(
  documentNumber: 'UT1234567',
  birthDate: PartialDate(1990, 5, 15),
  expiryDate: DateTime.utc(2034, 3, 13),
);
IcaoAccessKey.fromMrz(scannedLines);        // check digits verified
```

PACE is used when the chip offers it, BAC otherwise. Identity cards issued
since 2021 open with PACE only; older passports with BAC only, from the MRZ.
A key the chip refuses throws an `IcaoAccessException` whose `reason` is
`wrongKey`.

## Read on arrival

```dart
final watcher = IcaoWatcher(
  CcidTerminal.any(),         // every reader, those plugged in later included
  accessKey: null,            // a key known in advance, tried first
  accessPrompt: (request) => askForCan(request), // null when the user gives up
  autoRead: true,             // read as soon as the document is put down
  parts: IcaoPart.all,        // face, signature, personalDetails, ...
  acceptExpired: false,       // turn down expired documents
  acceptedTypes: null,        // every document type
  verifySignatures: true,     // Passive Authentication
  trustedRoots: null,         // the CSCAs, see below
  verifyCard: true,           // have the chip prove it is genuine
  showPrivateData: false,     // the personal numbers, see Personal data
  onProgress: null,           // 0 to 1, for a progress bar
  onApdu: null,               // every command and answer, before protection
)..start();

watcher.events.listen((event) {
  switch (event) {
    case IcaoChipRead read:
      show(read.document);
    case IcaoChipReadFailed failed:
      showError(icaoErrorMessage(failed.error, IcaoLanguage.fr));
    case IcaoChipRemoved _:
      clear();
    case IcaoChipInserted _:
      break;
  }
});
```

`request.acceptsCan` tells whether the CAN opens this chip, and
`request.refused` why the previous key was turned down. The prompt is asked
again until the chip opens or it returns null.

The watcher checks that the document is still there with a harmless
command. It never sends one during a read, which would end secure messaging.

## Read less

```dart
final document = await reader.read(access: key, parts: {IcaoPart.face});
document.personalDetails;   // null
```

DG1 is always read. DG2 is the largest file and most of the reading time:
leave `IcaoPart.face` out when the photo is not needed.

## Turn documents down

Three checks are on by default: an expired document, data the issuing
state did not sign and a cloned chip are turned down. `acceptedTypes` adds
a fourth:

```dart
await reader.read(access: key, acceptedTypes: {IcaoDocumentType.passport});
```

A document turned down throws an `IcaoDocumentRejectedException` whose
`reason` is `expired`, `documentType`, `signature` or `notGenuine`.

- `verifySignatures` runs Passive Authentication: every data group read must
  match its hash in EF.SOD, which the document signer signed. With
  `trustedRoots`, a CSCA among them must have issued the document signer.
- `verifyCard` has the chip prove it holds a private key that a copy of the
  files would not: Chip Authentication from DG14, Chip Authentication
  Mapping during PACE, or Active Authentication from DG15. It needs
  `verifySignatures`, which vouches for those keys. A chip offering none of
  them, as on some older passports, gives `notSupported`.

## Trust the issuing states

The certificates of the issuing states (CSCAs) are not bundled: they change,
and states publish them.

```dart
final list = IcaoMasterList.parse(bytes);
await reader.read(access: key, trustedRoots: list.cscas);
```

`IcaoMasterList.parse` reads:

- the German master list, a `.ml` file in the ZIP the
  [BSI publishes](https://www.bsi.bund.de/SharedDocs/Downloads/DE/BSI/ElekAusweise/CSCA/GermanMasterList.html);
- the LDIF files of the [ICAO PKD download](https://download.pkd.icao.int);
- certificates in PEM or DER.

Without `trustedRoots`, the hashes and the signature are still checked, and
`passiveAuthentication.chain` is `unverified`: the data is consistent, but
nothing ties its signer to a state. Anyone can make a chip that passes every
check that way, its own proof included: to establish an identity, give the
CSCAs.

A CSCA of any state in the list is accepted for any document. To require
the issuing state's own, pass only its CSCAs (`list.ofCountry('BE')`), or
compare `passiveAuthentication.countrySigningCa?.subject.country` with the
issuing state of the MRZ. Revocation lists are not checked.

## Check on a server

```dart
// On the device.
send(document.toJson());

// On the server.
final copy = IcaoDocument.fromJson(json);
final check = IcaoPassiveAuthenticator(trustedRoots: list.cscas)
    .verify(sod: copy.sod, dataGroups: copy.dataGroups);
check.isValid;
```

Passive Authentication needs no chip. The chip's own proof, though, only
happens while it is on the reader.

## Images

`document.photo` is ready for Flutter's `Image.memory`, whatever the chip
holds: a JPEG as it is, or a PNG converted from JPEG 2000, which most
identity cards and many passports use and Flutter does not decode. The
decoder is built in, written in pure Dart from ITU-T T.800: no plugin, no
server.

```dart
Image.memory(document.photo!);
document.face?.bytes;          // the image as the chip holds it
document.face?.format;         // jpeg, jpeg2000 or png
```

Every `IcaoImage`, the signature of DG7 and the images of DG12 included,
has its `displayBytes` in the same way. The PNG is lossless: it holds the
pixels of the JPEG 2000 image, decoded once, when the image is read. The
bytes the issuing state signed stay in `bytes`.

## Without a reader

```dart
import 'package:eid_icao/testing.dart';

final chip = SimulatedIcaoChip(lastName: 'PEETERS', can: '654321');
final document = await IcaoReader(chip).read(access: chip.canKey);
chip.remove();
chip.insert();
```

It holds a fictional citizen of Utopia, the state of the ICAO specimens,
signed by a made-up CSCA trusted for the simulator alone. `access`
(`paceAndBac`, `paceOnly`, `bacOnly`), `proof`, `faceEncoding`,
`tamperedGroup` and `cloned` give the documents the checks meet in the
field, and those they turn down. `photo: specimenPhotoJpeg2000` gives it
the JPEG 2000 face of most identity cards.

## Not covered

- DG3 and DG4, fingerprints and irises: they need Extended Access Control
  with terminal certificates that states issue to their own authorities.
- PACE with Integrated Mapping, which few chips offer.
- Revocation lists, and the LDS2 applications (travel records, visas).
- JPEG 2000 beyond part 1: the extensions of part 2 and the high throughput
  coding of part 15, which ICAO documents do not use.
- Reading the MRZ with a camera.

## Personal data

A chip holds the holder's personal data and photo, which data protection
law covers. Read it only with a reason the holder knows, keep what you need,
and do not store the CAN or the MRZ key longer than the read. `onApdu`
reports the data read, though never the keys.

`showPrivateData` is off by default. The personal numbers are then left
out: the optional data of the MRZ, where Belgium puts the national register
number and passports a personal number, and the personal number of DG11.
Most uses do not need them, and some states restrict who may use them, as
Belgium does for its national register number.

```dart
await reader.read(access: key);                        // mrz.optionalData is empty
await reader.read(access: key, showPrivateData: true); // and here it is
```

The signatures are still checked on the files as read. Without the
numbers, the document leaves out the raw DG1 and DG11 that hold them, so a
server receiving `toJson()` gets the MRZ as text and cannot check DG1 again;
`onApdu` gets their answers with the data zeroed.

## Sources

- ICAO Doc 9303, eighth edition: parts 3 to 6 (MRZ), 10 (LDS), 11 (BAC,
  PACE, Chip and Active Authentication, with the worked examples this
  package is tested against) and 12 (PKI).
- BSI TR-03110 and TR-03111.
- ISO/IEC 19794-5:2005, and ISO/IEC 39794-5. This software makes use of the
  Schema from ISO/IEC 39794-5 within modifications permitted in the
  relevant ISO/IEC standard.
- RFC 5114 (DH groups), RFC 5652 (CMS), RFC 8017 (RSA).

## License

Released under the [MIT licence](https://pub.dev/packages/eid_icao/license).

## More from COMAPPS

Electronic identity cards in Dart:

| Package | What it does |
| --- | --- |
| [eid](https://pub.dev/packages/eid) | APDUs, ISO 7816-4 file reading and the values national cards share. |
| [eid_belgium](https://pub.dev/packages/eid_belgium) | The Belgian eID, Kids ID and residence cards, through their contact chip. |
| [eid_ccid](https://pub.dev/packages/eid_ccid) | The transport for a USB or PC/SC card reader. |
| [eid_nfc](https://pub.dev/packages/eid_nfc) | The transport for the NFC of an Android phone or an iPhone. |

Every package COMAPPS publishes is listed at
[packages.comapps.be](https://packages.comapps.be).
