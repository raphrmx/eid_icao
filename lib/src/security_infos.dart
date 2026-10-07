import 'dart:typed_data';

import 'package:eid_icao/src/crypto/cipher.dart';
import 'package:eid_icao/src/crypto/dh.dart';
import 'package:eid_icao/src/crypto/ec.dart';
import 'package:eid_icao/src/crypto/named_parameters.dart';
import 'package:eid_icao/src/crypto/public_key.dart';
import 'package:eid_icao/src/tlv.dart';

const _bsi = '0.4.0.127.0.7.2.2';

/// id-PACE.
const pacePrefix = '$_bsi.4';

/// id-CA.
const chipAuthenticationPrefix = '$_bsi.3';

/// id-AA.
const activeAuthenticationOid = '2.23.136.1.1.5';

/// How PACE maps the nonce to a generator.
enum PaceMapping {
  /// Generic Mapping.
  generic,

  /// Integrated Mapping, not supported.
  integrated,

  /// Chip Authentication Mapping: Generic Mapping that also authenticates
  /// the chip.
  chipAuthentication,
}

/// A PACEInfo: one PACE variant the chip offers.
final class PaceInfo {
  /// The variant of [objectIdentifier], with [parameterId] when it uses
  /// standardized domain parameters.
  const PaceInfo(this.objectIdentifier, this.version, this.parameterId);

  /// The protocol, such as id-PACE-ECDH-GM-AES-CBC-CMAC-128.
  final String objectIdentifier;

  /// The protocol version, 2.
  final int version;

  /// The standardized domain parameters, or null when a
  /// PACEDomainParameterInfo gives them.
  final int? parameterId;

  /// Whether the key agreement is ECDH rather than DH.
  bool get isElliptic {
    final kind = _kind;
    return kind == 2 || kind == 4 || kind == 6;
  }

  /// The mapping, or null for an unknown variant.
  PaceMapping? get mapping => switch (_kind) {
        1 || 2 => PaceMapping.generic,
        3 || 4 => PaceMapping.integrated,
        6 => PaceMapping.chipAuthentication,
        _ => null,
      };

  /// The cipher, or null for an unknown variant.
  SymmetricCipher? get cipher => _cipherOf(objectIdentifier);

  /// Whether this package can run the variant.
  bool get isSupported =>
      version == 2 &&
      cipher != null &&
      mapping != null &&
      mapping != PaceMapping.integrated &&
      !(mapping == PaceMapping.chipAuthentication && cipher!.isAes == false);

  int? get _kind {
    final parts = objectIdentifier.substring(pacePrefix.length).split('.');
    return parts.length == 3 ? int.tryParse(parts[1]) : null;
  }
}

/// A ChipAuthenticationInfo: one Chip Authentication variant.
final class ChipAuthenticationInfo {
  /// The variant of [objectIdentifier] for the key [keyId].
  const ChipAuthenticationInfo(this.objectIdentifier, this.version, this.keyId);

  /// The protocol, such as id-CA-ECDH-AES-CBC-CMAC-128.
  final String objectIdentifier;

  /// The version: 1 for 3DES, 2 for AES.
  final int version;

  /// The key it applies to when the chip has several.
  final int? keyId;

  /// The cipher, or null for an unknown variant.
  SymmetricCipher? get cipher => _cipherOf(objectIdentifier);
}

/// A ChipAuthenticationPublicKeyInfo: the chip's static key agreement key.
final class ChipAuthenticationPublicKey {
  /// The key [publicKey], identified by [keyId].
  const ChipAuthenticationPublicKey(this.publicKey, this.keyId);

  /// The EC or DH public key.
  final PublicKey publicKey;

  /// The identifier matching a [ChipAuthenticationInfo], when there are
  /// several.
  final int? keyId;
}

/// What the chip lists in EF.CardAccess, EF.CardSecurity or DG14.
final class SecurityInfos {
  SecurityInfos._(
    this.pace,
    this.paceDomainParameters,
    this.chipAuthentication,
    this.chipAuthenticationKeys,
    this.activeAuthenticationSignature,
  );

  /// Reads a SET OF SecurityInfo. Entries this package does not know are
  /// skipped. Throws a [FormatException] when [bytes] are no such set.
  factory SecurityInfos.parse(Uint8List bytes) =>
      parseUntrusted(() => SecurityInfos._parseUnchecked(bytes));

  factory SecurityInfos._parseUnchecked(Uint8List bytes) {
    final set = Tlv.parse(bytes);
    if (set.tag != 0x31) throw const FormatException('Not a SecurityInfos');
    final pace = <PaceInfo>[];
    final domains = <int?, Object>{};
    final chip = <ChipAuthenticationInfo>[];
    final keys = <ChipAuthenticationPublicKey>[];
    String? activeSignature;
    for (final info in set.children) {
      final fields = info.children;
      if (info.tag != 0x30 || fields.isEmpty || fields[0].tag != 0x06) {
        continue;
      }
      final oid = fields[0].objectIdentifier;
      int? optionalInteger(int index) =>
          fields.length > index && fields[index].tag == 0x02
              ? fields[index].smallInteger
              : null;
      if (oid.startsWith('$pacePrefix.') && oid.split('.').length == 11) {
        pace.add(PaceInfo(oid, optionalInteger(1) ?? 0, optionalInteger(2)));
      } else if (oid.startsWith('$pacePrefix.') && fields.length > 1) {
        // PACEDomainParameterInfo: an AlgorithmIdentifier, then an id.
        final algorithm = fields[1].children;
        if (algorithm.length < 2) continue;
        final parameters = switch (algorithm[0].objectIdentifier) {
          '1.2.840.10045.2.1' => ecParameters(algorithm[1]),
          _ => dhParameters(algorithm[1]),
        };
        domains[optionalInteger(2)] = parameters;
      } else if (oid.startsWith('$chipAuthenticationPrefix.') &&
          oid.split('.').length == 11) {
        chip.add(ChipAuthenticationInfo(
          oid,
          optionalInteger(1) ?? 0,
          optionalInteger(2),
        ));
      } else if (oid.startsWith('$_bsi.1.') && fields.length > 1) {
        keys.add(ChipAuthenticationPublicKey(
          PublicKey.fromTlv(fields[1]),
          optionalInteger(2),
        ));
      } else if (oid == activeAuthenticationOid && fields.length > 2) {
        activeSignature = fields[2].objectIdentifier;
      }
    }
    return SecurityInfos._(
      List.unmodifiable(pace),
      Map.unmodifiable(domains),
      List.unmodifiable(chip),
      List.unmodifiable(keys),
      activeSignature,
    );
  }

  /// The PACE variants offered.
  final List<PaceInfo> pace;

  /// Proprietary PACE domain parameters, an [EcCurve] or a [DhGroup], by
  /// parameter identifier (null when there is a single set).
  final Map<int?, Object> paceDomainParameters;

  /// The Chip Authentication variants offered.
  final List<ChipAuthenticationInfo> chipAuthentication;

  /// The Chip Authentication keys.
  final List<ChipAuthenticationPublicKey> chipAuthenticationKeys;

  /// The signature algorithm of Active Authentication with an EC key, from
  /// its ActiveAuthenticationInfo.
  final String? activeAuthenticationSignature;

  /// The domain parameters of [info]: standardized, or proprietary.
  Object? domainParametersOf(PaceInfo info) {
    final id = info.parameterId;
    return paceDomainParameters[id] ??
        (paceDomainParameters.length == 1 && id == null
            ? paceDomainParameters.values.first
            : null) ??
        (id == null ? null : standardizedDomainParameters[id]);
  }

  /// The PACE variant to run, Chip Authentication Mapping, ECDH and AES
  /// preferred.
  PaceInfo? get preferredPace {
    final supported = pace.where(
      (info) => info.isSupported && domainParametersOf(info) != null,
    );
    PaceInfo? best;
    for (final info in supported) {
      if (best == null || _rank(info) > _rank(best)) best = info;
    }
    return best;
  }

  // Chip Authentication Mapping first, then ECDH, then AES.
  static int _rank(PaceInfo info) =>
      (info.mapping == PaceMapping.chipAuthentication ? 8 : 0) +
      (info.isElliptic ? 4 : 0) +
      (info.cipher!.isAes ? 2 : 0);
}

SymmetricCipher? _cipherOf(String oid) => switch (oid.split('.').last) {
      '1' => SymmetricCipher.tripleDes,
      '2' => SymmetricCipher.aes128,
      '3' => SymmetricCipher.aes192,
      '4' => SymmetricCipher.aes256,
      _ => null,
    };
