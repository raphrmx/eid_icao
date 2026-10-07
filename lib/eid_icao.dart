/// Reads the chip of passports and identity cards, ICAO 9303: BAC and
/// PACE, the MRZ, the face and the other data groups, with Passive, Chip
/// and Active Authentication.
///
/// An [IcaoReader] works over any `CardTransport` from the `eid` package,
/// such as a contactless reader through `eid_ccid`.
library;

export 'package:eid/eid.dart';

export 'src/access_key.dart';
export 'src/certificate.dart' show IcaoCertificate, IcaoName;
export 'src/document.dart';
export 'src/exceptions.dart';
export 'src/image.dart' show IcaoImage, IcaoImageFormat;
export 'src/lds.dart'
    show
        IcaoDataGroup,
        IcaoDocumentDetails,
        IcaoFace,
        IcaoFaceEncoding,
        IcaoPersonToNotify,
        IcaoPersonalDetails;
export 'src/master_list.dart';
export 'src/messages.dart';
export 'src/mrz.dart';
export 'src/passive_authentication.dart';
export 'src/reader.dart';
export 'src/watcher.dart';
