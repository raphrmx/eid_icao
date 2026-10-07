"""Builds test/openssl_pki.dart: a throwaway ICAO PKI made with OpenSSL, so
the Dart parsers and checks are tested against an independent encoder.

Run from the package root: python tool/make_test_pki.py
"""
import base64
import hashlib
import os
import subprocess
import tempfile


def run(*args):
    result = subprocess.run(args, capture_output=True)
    if result.returncode:
        raise SystemExit(result.stderr.decode())
    return result.stdout


def der_len(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([0x80 | len(b)]) + b


def tlv(tag, value):
    return bytes.fromhex(tag) + der_len(len(value)) + value


def integer(n):
    return tlv('02', n.to_bytes(max(1, (n.bit_length() + 8) // 8), 'big'))


def oid(dotted):
    parts = [int(part) for part in dotted.split('.')]
    out = bytearray([parts[0] * 40 + parts[1]])
    for part in parts[2:]:
        groups = [part & 0x7F]
        part >>= 7
        while part:
            groups.insert(0, (part & 0x7F) | 0x80)
            part >>= 7
        out += bytes(groups)
    return tlv('06', bytes(out))


def seq(*items):
    return tlv('30', b''.join(items))


work = tempfile.mkdtemp()


def p(name):
    return os.path.join(work, name)


counter = [0]


def config(text):
    counter[0] += 1
    path = p('config%d.cnf' % counter[0])
    with open(path, 'w') as file:
        file.write(text)
    return path


REQ = '[req]\ndistinguished_name=dn\n[dn]\n'
CA_EXT = ('[v3]\nbasicConstraints=critical,CA:true,pathlen:0\n'
          'keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n')
DS_EXT = ('keyUsage=critical,digitalSignature\nsubjectKeyIdentifier=hash\n'
          'authorityKeyIdentifier=keyid\n')
PSS = ['-sigopt', 'rsa_padding_mode:pss', '-sigopt', 'rsa_pss_saltlen:32']


def ca(name, key, subject, serial, *options):
    run('openssl', 'req', '-x509', '-new', '-key', p(key), '-days', '7300',
        '-subj', subject, '-config', config(REQ + CA_EXT),
        '-extensions', 'v3', '-set_serial', serial, *options,
        '-out', p(name))


def signer(name, key, subject, ca_name, ca_key, serial, *options):
    run('openssl', 'req', '-new', '-key', p(key), '-subj', subject,
        '-config', config(REQ), '-out', p(name + '.csr'))
    run('openssl', 'x509', '-req', '-in', p(name + '.csr'), '-CA', p(ca_name),
        '-CAkey', p(ca_key), '-days', '3650', '-set_serial', serial,
        '-extfile', config(DS_EXT), *options, '-out', p(name))


# EC: brainpool curves with explicit parameters, as ICAO certificates carry.
for curve, key in [('brainpoolP384r1', 'csca_ec.key'),
                   ('brainpoolP256r1', 'dsc_ec.key')]:
    run('openssl', 'ecparam', '-name', curve, '-param_enc', 'explicit',
        '-genkey', '-noout', '-out', p(key))
ca('csca_ec.pem', 'csca_ec.key', '/C=UT/O=Utopia/CN=CSCA Utopia EC', '1',
   '-sha384')
signer('dsc_ec.pem', 'dsc_ec.key', '/C=UT/O=Utopia/CN=Document Signer EC',
       'csca_ec.pem', 'csca_ec.key', '2', '-sha384')

# RSA, signed with PSS.
for bits, key in [('3072', 'csca_rsa.key'), ('2048', 'dsc_rsa.key')]:
    run('openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt',
        'rsa_keygen_bits:' + bits, '-out', p(key))
ca('csca_rsa.pem', 'csca_rsa.key', '/C=UT/O=Utopia/CN=CSCA Utopia RSA', '3',
   '-sha256', *PSS)
signer('dsc_rsa.pem', 'dsc_rsa.key', '/C=UT/O=Utopia/CN=Document Signer RSA',
       'csca_rsa.pem', 'csca_rsa.key', '4', '-sha256', *PSS)


def der_of(pem):
    return run('openssl', 'x509', '-in', p(pem), '-outform', 'DER')


# Two data groups of the ICAO TD3 specimen and their LDSSecurityObject.
mrz = (b'P<UTOERIKSSON<<ANNA<MARIA<<<<<<<<<<<<<<<<<<<'
       b'L898902C36UTO7408122F1204159ZE184226B<<<<<10')
dg1 = tlv('61', tlv('5F1F', mrz))
dg2 = tlv('75', b'\x01\x02\x03\x04')
lds = seq(integer(0), seq(oid('2.16.840.1.101.3.4.2.1')),
          seq(seq(integer(1), tlv('04', hashlib.sha256(dg1).digest())),
              seq(integer(2), tlv('04', hashlib.sha256(dg2).digest()))))
with open(p('lds.der'), 'wb') as file:
    file.write(lds)


def cms(content, cert, key, content_type, *options):
    return run('openssl', 'cms', '-sign', '-binary', '-nodetach',
               '-nosmimecap', '-in', p(content), '-signer', p(cert),
               '-inkey', p(key), '-md', 'sha256',
               '-econtent_type', content_type, '-outform', 'DER', *options)


sod_ec = tlv('77', cms('lds.der', 'dsc_ec.pem', 'dsc_ec.key',
                       '2.23.136.1.1.1'))
sod_rsa = tlv('77', cms('lds.der', 'dsc_rsa.pem', 'dsc_rsa.key',
                        '2.23.136.1.1.1', '-keyopt',
                        'rsa_padding_mode:pss'))
# The older content type Belgium still declares in its EF.SOD.
sod_old_type = tlv('77', cms('lds.der', 'dsc_ec.pem', 'dsc_ec.key',
                             '1.3.27.1.1.1'))
cscas = sorted([der_of('csca_ec.pem'), der_of('csca_rsa.pem')])
with open(p('ml.der'), 'wb') as file:
    file.write(seq(integer(0), tlv('31', b''.join(cscas))))
master_list = cms('ml.der', 'dsc_ec.pem', 'dsc_ec.key', '2.23.136.1.1.2')


# Active Authentication answers, ISO 9796-2 scheme 1 and plain ECDSA.
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature)

challenge = bytes.fromhex('0123456789ABCDEF')
aa_rsa = rsa.generate_private_key(public_exponent=65537, key_size=1024)
numbers = aa_rsa.private_numbers()
n = numbers.public_numbers.n
k = (n.bit_length() + 7) // 8
m1 = os.urandom(k - 20 - 2)
f = bytes([0x6A]) + m1 + hashlib.sha1(m1 + challenge).digest() + bytes([0xBC])
s_value = pow(int.from_bytes(f, 'big'), numbers.d, n)
# ISO 9796-2 lets the signer send min(s, n - s).
aa_rsa_signature = min(s_value, n - s_value).to_bytes(k, 'big')
aa_ec = ec.generate_private_key(ec.BrainpoolP256R1())
r, s_ec = decode_dss_signature(
    aa_ec.sign(challenge, ec.ECDSA(hashes.SHA256())))
aa_ec_signature = r.to_bytes(32, 'big') + s_ec.to_bytes(32, 'big')


def spki(key):
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo)


def constant(name, data):
    text = base64.b64encode(data).decode()
    lines = [text[i:i + 70] for i in range(0, len(text), 70)]
    body = '\n'.join("  '%s'" % line for line in lines)
    return 'final %s = base64Decode(\n%s,\n);\n' % (name, body)


parts = [
    '// Generated by tool/make_test_pki.py with OpenSSL. Throwaway keys.',
    '',
    "import 'dart:convert';",
    '',
]
for name, data in [('cscaEc', der_of('csca_ec.pem')),
                   ('dscEc', der_of('dsc_ec.pem')),
                   ('cscaRsa', der_of('csca_rsa.pem')),
                   ('dscRsa', der_of('dsc_rsa.pem')),
                   ('dg1', dg1), ('dg2', dg2),
                   ('sodEc', sod_ec), ('sodRsaPss', sod_rsa),
                   ('sodOldType', sod_old_type),
                   ('masterList', master_list),
                   ('aaChallenge', challenge),
                   ('aaRsaKey', spki(aa_rsa)),
                   ('aaRsaSignature', aa_rsa_signature),
                   ('aaEcKey', spki(aa_ec)),
                   ('aaEcSignature', aa_ec_signature)]:
    parts.append(constant(name, data))
with open('test/openssl_pki.dart', 'w', newline='\n') as file:
    file.write('\n'.join(parts))
print(run('openssl', 'asn1parse', '-in', p('dsc_ec.pem')).decode()[:1500])
