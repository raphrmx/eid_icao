## 0.1.0

- First release: reads ICAO 9303 passports and identity cards over any
  `eid` transport.
- Access with BAC or PACE (Generic Mapping and Chip Authentication Mapping,
  ECDH and DH), from the MRZ or the CAN; secure messaging in 3DES and AES.
- Decodes DG1 (MRZ, TD1, TD2 and TD3), DG2 (ISO/IEC 19794-5 and 39794-5),
  DG7, DG11, DG12 and DG16; keeps every data group read as it was read.
- `IcaoDocument.photo` and `IcaoImage.displayBytes`: the images as JPEG or
  PNG, ready to show. JPEG 2000 is decoded in pure Dart (ITU-T T.800 part
  1) and converted to PNG without loss.
- Passive Authentication up to the CSCAs of a master list
  (`IcaoMasterList`: CMS, ICAO PKD LDIF, PEM, DER), RSA PKCS #1, RSA-PSS and
  ECDSA, named or explicit curves.
- Chip Authentication, Chip Authentication Mapping and Active
  Authentication (RSA ISO 9796-2, ECDSA).
- `IcaoWatcher` reads each document put on the reader, asking for its key.
- Options: `parts`, `acceptExpired`, `acceptedTypes`, `verifySignatures`,
  `trustedRoots`, `verifyCard`, `showPrivateData`, `onApdu`, `onProgress`.
- `showPrivateData` is off by default: the personal numbers of the MRZ and
  DG11, such as the Belgian national register number, are left out.
- `toJson` and `fromJson`, and `IcaoPassiveAuthenticator` to check again on
  a server.
- Error messages in French, Dutch, German and English.
- `SimulatedIcaoChip` stands in for a document and a reader;
  `specimenPhotoJpeg2000` gives it a JPEG 2000 face.
