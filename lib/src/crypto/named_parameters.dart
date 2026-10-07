import 'package:eid_icao/src/crypto/dh.dart';
import 'package:eid_icao/src/crypto/ec.dart';

// Domain parameters from pointycastle's curve definitions and RFC 5114.

BigInt _hex(String hex) => BigInt.parse(hex, radix: 16);

/// NIST P-192.
final secp192r1 = EcCurve(
  name: 'NIST P-192',
  objectIdentifier: '1.2.840.10045.3.1.1',
  p: _hex('fffffffffffffffffffffffffffffffeffffffffffffffff'),
  a: _hex('fffffffffffffffffffffffffffffffefffffffffffffffc'),
  b: _hex('64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1'),
  gx: _hex('188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012'),
  gy: _hex('7192b95ffc8da78631011ed6b24cdd573f977a11e794811'),
  n: _hex('ffffffffffffffffffffffff99def836146bc9b1b4d22831'),
  h: BigInt.from(1),
);

/// brainpoolP192r1.
final brainpoolP192r1 = EcCurve(
  name: 'brainpoolP192r1',
  objectIdentifier: '1.3.36.3.3.2.8.1.1.3',
  p: _hex('c302f41d932a36cda7a3463093d18db78fce476de1a86297'),
  a: _hex('6a91174076b1e0e19c39c031fe8685c1cae040e5c69a28ef'),
  b: _hex('469a28ef7c28cca3dc721d044f4496bcca7ef4146fbf25c9'),
  gx: _hex('c0a0647eaab6a48753b033c56cb0f0900a2f5c4853375fd6'),
  gy: _hex('14b690866abd5bb88b5f4828c1490002e6773fa2fa299b8f'),
  n: _hex('c302f41d932a36cda7a3462f9e9e916b5be8f1029ac4acc1'),
  h: BigInt.from(1),
);

/// NIST P-224.
final secp224r1 = EcCurve(
  name: 'NIST P-224',
  objectIdentifier: '1.3.132.0.33',
  p: _hex('ffffffffffffffffffffffffffffffff000000000000000000000001'),
  a: _hex('fffffffffffffffffffffffffffffffefffffffffffffffffffffffe'),
  b: _hex('b4050a850c04b3abf54132565044b0b7d7bfd8ba270b39432355ffb4'),
  gx: _hex('b70e0cbd6bb4bf7f321390b94a03c1d356c21122343280d6115c1d21'),
  gy: _hex('bd376388b5f723fb4c22dfe6cd4375a05a07476444d5819985007e34'),
  n: _hex('ffffffffffffffffffffffffffff16a2e0b8f03e13dd29455c5c2a3d'),
  h: BigInt.from(1),
);

/// brainpoolP224r1.
final brainpoolP224r1 = EcCurve(
  name: 'brainpoolP224r1',
  objectIdentifier: '1.3.36.3.3.2.8.1.1.5',
  p: _hex('d7c134aa264366862a18302575d1d787b09f075797da89f57ec8c0ff'),
  a: _hex('68a5e62ca9ce6c1c299803a6c1530b514e182ad8b0042a59cad29f43'),
  b: _hex('2580f63ccfe44138870713b1a92369e33e2135d266dbb372386c400b'),
  gx: _hex('d9029ad2c7e5cf4340823b2a87dc68c9e4ce3174c1e6efdee12c07d'),
  gy: _hex('58aa56f772c0726f24c6b89e4ecdac24354b9e99caa3f6d3761402cd'),
  n: _hex('d7c134aa264366862a18302575d0fb98d116bc4b6ddebca3a5a7939f'),
  h: BigInt.from(1),
);

/// NIST P-256.
final secp256r1 = EcCurve(
  name: 'NIST P-256',
  objectIdentifier: '1.2.840.10045.3.1.7',
  p: _hex('ffffffff00000001000000000000000000000000ffffffffffffffffffffffff'),
  a: _hex('ffffffff00000001000000000000000000000000fffffffffffffffffffffffc'),
  b: _hex('5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b'),
  gx: _hex('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296'),
  gy: _hex('4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5'),
  n: _hex('ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551'),
  h: BigInt.from(1),
);

/// brainpoolP256r1.
final brainpoolP256r1 = EcCurve(
  name: 'brainpoolP256r1',
  objectIdentifier: '1.3.36.3.3.2.8.1.1.7',
  p: _hex('a9fb57dba1eea9bc3e660a909d838d726e3bf623d52620282013481d1f6e5377'),
  a: _hex('7d5a0975fc2c3057eef67530417affe7fb8055c126dc5c6ce94a4b44f330b5d9'),
  b: _hex('26dc5c6ce94a4b44f330b5d9bbd77cbf958416295cf7e1ce6bccdc18ff8c07b6'),
  gx: _hex('8bd2aeb9cb7e57cb2c4b482ffc81b7afb9de27e1e3bd23c23a4453bd9ace3262'),
  gy: _hex('547ef835c3dac4fd97f8461a14611dc9c27745132ded8e545c1d54c72f046997'),
  n: _hex('a9fb57dba1eea9bc3e660a909d838d718c397aa3b561a6f7901e0e82974856a7'),
  h: BigInt.from(1),
);

/// brainpoolP320r1.
final brainpoolP320r1 = EcCurve(
  name: 'brainpoolP320r1',
  objectIdentifier: '1.3.36.3.3.2.8.1.1.9',
  p: _hex('d35e472036bc4fb7e13c785ed201e065f98fcfa6f6f40def4f92b9ec7893ec28'
      'fcd412b1f1b32e27'),
  a: _hex('3ee30b568fbab0f883ccebd46d3f3bb8a2a73513f5eb79da66190eb085ffa9f4'
      '92f375a97d860eb4'),
  b: _hex('520883949dfdbc42d3ad198640688a6fe13f41349554b49acc31dccd88453981'
      '6f5eb4ac8fb1f1a6'),
  gx: _hex('43bd7e9afb53d8b85289bcc48ee5bfe6f20137d10a087eb6e7871e2a10a599c7'
      '10af8d0d39e20611'),
  gy: _hex('14fdd05545ec1cc8ab4093247f77275e0743ffed117182eaa9c77877aaac6ac7'
      'd35245d1692e8ee1'),
  n: _hex('d35e472036bc4fb7e13c785ed201e065f98fcfa5b68f12a32d482ec7ee8658e9'
      '8691555b44c59311'),
  h: BigInt.from(1),
);

/// NIST P-384.
final secp384r1 = EcCurve(
  name: 'NIST P-384',
  objectIdentifier: '1.3.132.0.34',
  p: _hex('fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe'
      'ffffffff0000000000000000ffffffff'),
  a: _hex('fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe'
      'ffffffff0000000000000000fffffffc'),
  b: _hex('b3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875a'
      'c656398d8a2ed19d2a85c8edd3ec2aef'),
  gx: _hex('aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a38'
      '5502f25dbf55296c3a545e3872760ab7'),
  gy: _hex('3617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c0'
      '0a60b1ce1d7e819d7a431d7c90ea0e5f'),
  n: _hex('ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf'
      '581a0db248b0a77aecec196accc52973'),
  h: BigInt.from(1),
);

/// brainpoolP384r1.
final brainpoolP384r1 = EcCurve(
  name: 'brainpoolP384r1',
  objectIdentifier: '1.3.36.3.3.2.8.1.1.11',
  p: _hex('8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b412b1da197fb71123'
      'acd3a729901d1a71874700133107ec53'),
  a: _hex('7bc382c63d8c150c3c72080ace05afa0c2bea28e4fb22787139165efba91f90f'
      '8aa5814a503ad4eb04a8c7dd22ce2826'),
  b: _hex('4a8c7dd22ce28268b39b55416f0447c2fb77de107dcd2a62e880ea53eeb62d57'
      'cb4390295dbc9943ab78696fa504c11'),
  gx: _hex('1d1c64f068cf45ffa2a63a81b7c13f6b8847a3e77ef14fe3db7fcafe0cbd10e8'
      'e826e03436d646aaef87b2e247d4af1e'),
  gy: _hex('8abe1d7520f9c2a45cb1eb8e95cfd55262b70b29feec5864e19c054ff9912928'
      '0e4646217791811142820341263c5315'),
  n: _hex('8cb91e82a3386d280f5d6f7e50e641df152f7109ed5456b31f166e6cac0425a7'
      'cf3ab6af6b7fc3103b883202e9046565'),
  h: BigInt.from(1),
);

/// brainpoolP512r1.
final brainpoolP512r1 = EcCurve(
  name: 'brainpoolP512r1',
  objectIdentifier: '1.3.36.3.3.2.8.1.1.13',
  p: _hex('aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330871'
      '7d4d9b009bc66842aecda12ae6a380e62881ff2f2d82c68528aa6056583a48f3'),
  a: _hex('7830a3318b603b89e2327145ac234cc594cbdd8d3df91610a83441caea9863bc'
      '2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a72bf2c7b9e7c1ac4d77fc94ca'),
  b: _hex('3df91610a83441caea9863bc2ded5d5aa8253aa10a2ef1c98b9ac8b57f1117a7'
      '2bf2c7b9e7c1ac4d77fc94cadc083e67984050b75ebae5dd2809bd638016f723'),
  gx: _hex('81aee4bdd82ed9645a21322e9c4c6a9385ed9f70b5d916c1b43b62eef4d0098e'
      'ff3b1f78e2d0d48d50d1687b93b97d5f7c6d5047406a5e688b352209bcb9f822'),
  gy: _hex('7dde385d566332ecc0eabfa9cf7822fdf209f70024a57b1aa000c55b881f8111'
      'b2dcde494a5f485e5bca4bd88a2763aed1ca2b2fa8f0540678cd1e0f3ad80892'),
  n: _hex('aadd9db8dbe9c48b3fd4e6ae33c9fc07cb308db3b3c9d20ed6639cca70330870'
      '553e5c414ca92619418661197fac10471db1d381085ddaddb58796829ca90069'),
  h: BigInt.from(1),
);

/// NIST P-521.
final secp521r1 = EcCurve(
  name: 'NIST P-521',
  objectIdentifier: '1.3.132.0.35',
  p: _hex('1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      'fff'),
  a: _hex('1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      'ffc'),
  b: _hex('51953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109'
      'e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f'
      '00'),
  gx: _hex('c6858e06b70404e9cd9e3ecb662395b4429c648139053fb521f828af606b4d3d'
      'baa14b5e77efe75928fe1dc127a2ffa8de3348b3c1856a429bf97e7e31c2e5bd'
      '66'),
  gy: _hex('11839296a789a3bc0045c8a5fb42c7d1bd998f54449579b446817afbd17273e6'
      '62c97ee72995ef42640c550b9013fad0761353c7086a272c24088be94769fd16'
      '650'),
  n: _hex('1fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'
      'ffa51868783bf2f966b7fcc0148f709a5d03bb5c9b8899c47aebb6fb71e91386'
      '409'),
  h: BigInt.from(1),
);

/// The named curves, by OBJECT IDENTIFIER.
final namedCurves = {
  for (final curve in [
    secp192r1,
    brainpoolP192r1,
    secp224r1,
    brainpoolP224r1,
    secp256r1,
    brainpoolP256r1,
    brainpoolP320r1,
    secp384r1,
    brainpoolP384r1,
    brainpoolP512r1,
    secp521r1,
  ])
    curve.objectIdentifier!: curve,
};

/// The 1024-bit MODP group with 160-bit prime order subgroup, RFC 5114.
final modp1024 = DhGroup(
  name: '1024-bit MODP group with 160-bit prime order subgroup',
  p: _hex(
    'b10b8f96a080e01dde92de5eae5d54ec52c99fbcfb06a3c69a6a9dca52d23b61'
    '6073e28675a23d189838ef1e2ee652c013ecb4aea906112324975c3cd49b83bf'
    'accbdd7d90c4bd7098488e9c219a73724effd6fae5644738faa31a4ff55bccc0'
    'a151af5f0dc8b4bd45bf37df365c1a65e68cfda76d4da708df1fb2bc2e4a4371',
  ),
  g: _hex(
    'a4d1cbd5c3fd34126765a442efb99905f8104dd258ac507fd6406cff14266d31'
    '266fea1e5c41564b777e690f5504f213160217b4b01b886a5e91547f9e2749f4'
    'd7fbd7d3b9a92ee1909d0d2263f80a76a6a24c087a091f531dbf0a0169b6a28a'
    'd662a4d18e73afa32d779d5918d08bc8858f4dcef97c2a24855e6eeb22b3b2e5',
  ),
  q: _hex('f518aa8781a8df278aba4e7d64b7cb9d49462353'),
);

/// The 2048-bit MODP group with 224-bit prime order subgroup, RFC 5114.
final modp2048Q224 = DhGroup(
  name: '2048-bit MODP group with 224-bit prime order subgroup',
  p: _hex(
    'ad107e1e9123a9d0d660faa79559c51fa20d64e5683b9fd1b54b1597b61d0a75'
    'e6fa141df95a56dbaf9a3c407ba1df15eb3d688a309c180e1de6b85a1274a0a6'
    '6d3f8152ad6ac2129037c9edefda4df8d91e8fef55b7394b7ad5b7d0b6c12207'
    'c9f98d11ed34dbf6c6ba0b2c8bbc27be6a00e0a0b9c49708b3bf8a3170918836'
    '81286130bc8985db1602e714415d9330278273c7de31efdc7310f7121fd5a074'
    '15987d9adc0a486dcdf93acc44328387315d75e198c641a480cd86a1b9e587e8'
    'be60e69cc928b2b9c52172e413042e9b23f10b0e16e79763c9b53dcf4ba80a29'
    'e3fb73c16b8e75b97ef363e2ffa31f71cf9de5384e71b81c0ac4dffe0c10e64f',
  ),
  g: _hex(
    'ac4032ef4f2d9ae39df30b5c8ffdac506cdebe7b89998caf74866a08cfe4ffe3'
    'a6824a4e10b9a6f0dd921f01a70c4afaab739d7700c29f52c57db17c620a8652'
    'be5e9001a8d66ad7c17669101999024af4d027275ac1348bb8a762d0521bc98a'
    'e247150422ea1ed409939d54da7460cdb5f6c6b250717cbef180eb34118e98d1'
    '19529a45d6f834566e3025e316a330efbb77a86f0c1ab15b051ae3d428c8f8ac'
    'b70a8137150b8eeb10e183edd19963ddd9e263e4770589ef6aa21e7f5f2ff381'
    'b539cce3409d13cd566afbb48d6c019181e1bcfe94b30269edfe72fe9b6aa4bd'
    '7b5a0f1c71cfff4c19c418e1f6ec017981bc087f2a7065b384b890d3191f2bfa',
  ),
  q: _hex('801c0d34c58d93fe997177101f80535a4738cebcbf389a99b36371eb'),
);

/// The 2048-bit MODP group with 256-bit prime order subgroup, RFC 5114.
final modp2048Q256 = DhGroup(
  name: '2048-bit MODP group with 256-bit prime order subgroup',
  p: _hex(
    '87a8e61db4b6663cffbbd19c651959998ceef608660dd0f25d2ceed4435e3b00'
    'e00df8f1d61957d4faf7df4561b2aa3016c3d91134096faa3bf4296d830e9a7c'
    '209e0c6497517abd5a8a9d306bcf67ed91f9e6725b4758c022e0b1ef4275bf7b'
    '6c5bfc11d45f9088b941f54eb1e59bb8bc39a0bf12307f5c4fdb70c581b23f76'
    'b63acae1caa6b7902d52526735488a0ef13c6d9a51bfa4ab3ad8347796524d8e'
    'f6a167b5a41825d967e144e5140564251ccacb83e6b486f6b3ca3f7971506026'
    'c0b857f689962856ded4010abd0be621c3a3960a54e710c375f26375d7014103'
    'a4b54330c198af126116d2276e11715f693877fad7ef09cadb094ae91e1a1597',
  ),
  g: _hex(
    '3fb32c9b73134d0b2e77506660edbd484ca7b18f21ef205407f4793a1a0ba125'
    '10dbc15077be463fff4fed4aac0bb555be3a6c1b0c6b47b1bc3773bf7e8c6f62'
    '901228f8c28cbb18a55ae31341000a650196f931c77a57f2ddf463e5e9ec144b'
    '777de62aaab8a8628ac376d282d6ed3864e67982428ebc831d14348f6f2f9193'
    'b5045af2767164e1dfc967c1fb3f2e55a4bd1bffe83b9c80d052b985d182ea0a'
    'db2a3b7313d3fe14c8484b1e052588b9b7d2bbd2df016199ecd06e1557cd0915'
    'b3353bbb64e0ec377fd028370df92b52c7891428cdc67eb6184b523d1db246c3'
    '2f63078490f00ef8d647d148d47954515e2327cfef98c582664b4c0f6cc41659',
  ),
  q: _hex('8cf83642a709a097b447997640129da299b1a47d1eb3750ba308b0fe64f5fbd3'),
);

/// The standardized domain parameters of ICAO 9303 part 11, by identifier:
/// an [EcCurve] or a [DhGroup].
final Map<int, Object> standardizedDomainParameters = {
  0: modp1024,
  1: modp2048Q224,
  2: modp2048Q256,
  8: secp192r1,
  9: brainpoolP192r1,
  10: secp224r1,
  11: brainpoolP224r1,
  12: secp256r1,
  13: brainpoolP256r1,
  14: brainpoolP320r1,
  15: secp384r1,
  16: brainpoolP384r1,
  17: brainpoolP512r1,
  18: secp521r1,
};
