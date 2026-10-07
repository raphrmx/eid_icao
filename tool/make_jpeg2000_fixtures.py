"""Builds test/jpeg2000_fixtures.dart: small JPEG 2000 images made by two
independent encoders, OpenJPEG (through Pillow) and JJ2000, with what
OpenJPEG decodes them to, so the Dart decoder is tested against both.

Needs Pillow, and the JJ2000 encoder of the j2k package:
dart pub global activate j2k, or J2K_ENCODE set to another command.

Run from the package root: python tool/make_jpeg2000_fixtures.py
"""
import base64
import hashlib
import math
import os
import random
import shlex
import struct
import subprocess
import tempfile

from PIL import Image

ENCODE = shlex.split(os.environ.get('J2K_ENCODE', 'dart pub global run j2k:encode'))
WORK = tempfile.mkdtemp()


def picture(width, height, seed):
    """A smooth picture with a little noise, like a photo; no one's face."""
    rng = random.Random(seed)
    image = Image.new('RGB', (width, height))
    pixels = []
    for y in range(height):
        for x in range(width):
            r = 128 + 90 * math.sin(x / 7.0) * math.cos(y / 11.0)
            g = 120 + 80 * math.cos((x + y) / 13.0)
            b = 110 + 70 * math.sin(x * y / 300.0)
            pixels.append(tuple(
                max(0, min(255, int(v) + rng.randint(-2, 2))) for v in (r, g, b)))
    image.putdata(pixels)
    return image


def path(name):
    return os.path.join(WORK, name)


def openjpeg(image, **options):
    name = path('openjpeg.jp2' if not options.get('no_jp2') else 'openjpeg.j2k')
    image.save(name, **options)
    return open(name, 'rb').read()


def jj2000(image, *options):
    source = path('source.ppm' if image.mode == 'RGB' else 'source.pgm')
    image.save(source)
    out = path('jj2000.j2k')
    subprocess.run(ENCODE + ['-i', source, '-o', out, *options], check=True,
                   capture_output=True)
    return open(out, 'rb').read()


def decoded(data):
    """What OpenJPEG decodes data to, 8 bits per sample."""
    name = path('decode.j2k')
    open(name, 'wb').write(data)
    image = Image.open(name)
    image.load()
    if image.mode.startswith('I'):
        values = image.get_flattened_data()
        return image.size, 1, bytes((v * 255 + 32767) // 65535 for v in values)
    return image.size, len(image.getbands()), image.tobytes()


# Hand-made JP2 boxes, ISO/IEC 15444-1 annex I.
def box(kind, payload):
    return struct.pack('>I', 8 + len(payload)) + kind + payload


def jp2(codestream, height, width, components, *extra):
    header = box(b'ihdr', struct.pack('>IIHBBBB', height, width, components,
                                      7, 7, 0, 0))
    return (box(b'jP  ', b'\r\n\x87\n')
            + box(b'ftyp', b'jp2 ' + struct.pack('>I', 0) + b'jp2 ')
            + box(b'jp2h', header + b''.join(extra))
            + box(b'jp2c', codestream))


def colour(space):
    return box(b'colr', bytes([1, 0, 0]) + struct.pack('>I', space))


# A codestream split into its markers before the first SOT and its tile
# data, for codestreams of a single tile-part.
def split(codestream):
    sot = codestream.index(b'\xff\x90')
    sod = codestream.index(b'\xff\x93', sot)
    end = len(codestream) - 2
    assert codestream[end:] == b'\xff\xd9'
    return codestream[:sot], codestream[sod + 2:end]


def marker(header, code):
    at = header.index(code)
    length = struct.unpack('>H', header[at + 2:at + 4])[0]
    return header[at:at + 2 + length]


def subsampled(y, cb, cr):
    """One codestream from three grey ones, the chroma at half size: CPRL,
    so that the packets of each component follow one another."""
    parts = [split(openjpeg(c, irreversible=False, no_jp2=True,
                            num_resolutions=3)) for c in (y, cb, cr)]
    header = parts[0][0]
    width, height = y.size
    siz = struct.pack('>HHIIIIIIIIH', 47, 0, width, height, 0, 0, width,
                      height, 0, 0, 3) + bytes([7, 1, 1, 7, 2, 2, 7, 2, 2])
    cod = bytearray(marker(header, b'\xff\x52'))
    cod[5] = 4  # CPRL
    cod[8] = 0  # no colour transform
    qcd = marker(header, b'\xff\x5c')
    for other, _ in parts[1:]:
        assert marker(other, b'\xff\x5c') == qcd
    data = b''.join(tile for _, tile in parts)
    sot = struct.pack('>HHHIBB', 0xFF90, 10, 0, 12 + 2 + len(data), 0, 1)
    return (b'\xff\x4f\xff\x51' + siz + bytes(cod) + qcd + sot + b'\xff\x93'
            + data + b'\xff\xd9')


def main():
    small = picture(32, 40, 1)
    large = picture(48, 60, 2)
    grey = small.convert('L')
    fixtures = []

    def add(name, data, *, exact=True, expected=None):
        size, channels, pixels = expected or decoded(data)
        fixtures.append((name, data, size, channels, pixels, exact))

    add('lossless 5-3 RGB', openjpeg(small, irreversible=False))
    add('lossy 9-7 in three layers', openjpeg(
        small, irreversible=True, quality_mode='rates',
        quality_layers=[40, 20, 10]), exact=False)
    add('RLCP', openjpeg(small, irreversible=False, progression='RLCP',
                         quality_layers=[20, 0]))
    add('RPCL with precincts', openjpeg(
        large, irreversible=True, progression='RPCL', precinct_size=(32, 32),
        quality_layers=[30, 10]), exact=False)
    add('PCRL with small code-blocks', openjpeg(
        large, irreversible=False, progression='PCRL', precinct_size=(32, 32),
        codeblock_size=(8, 8)))
    add('CPRL over tiles', openjpeg(
        large, irreversible=True, progression='CPRL', precinct_size=(32, 16),
        tile_size=(24, 30), quality_layers=[20]), exact=False)
    add('tiles and image offsets', openjpeg(
        large, irreversible=False, tile_size=(16, 16), tile_offset=(5, 3),
        offset=(7, 11)))
    add('bare codestream with odd offsets', openjpeg(
        small, irreversible=False, offset=(3, 5), tile_size=(200, 200),
        no_jp2=True, num_resolutions=4))
    add('no colour transform', openjpeg(small, irreversible=False, mct=0))
    add('grey, 16 bits', openjpeg(
        grey.convert('I').point(lambda v: v * 257).convert('I;16'),
        irreversible=False))
    add('RGBA', openjpeg(Image.merge('RGBA', (*small.split(), grey)),
                         irreversible=False))
    add('grey and alpha', openjpeg(
        Image.merge('LA', (grey, grey.point(lambda v: 255 - v))),
        irreversible=False))
    add('1 by 1', openjpeg(small.resize((1, 1)), irreversible=False,
                           num_resolutions=1, no_jp2=True))

    add('every code-block mode', jj2000(
        small, '-rate', '3', '-Cbypass', 'on', '-CresetMQ', 'on',
        '-Cterminate', 'on', '-Ccausal', 'on', '-Cseg_symbol', 'on',
        '-Cterm_type', 'predict'), exact=False)
    add('every code-block mode, lossless', jj2000(
        small, '-lossless', 'on', '-Cbypass', 'on', '-CresetMQ', 'on',
        '-Cterminate', 'on', '-Ccausal', 'on', '-Cseg_symbol', 'on'))
    add('bypass, lossless', jj2000(small, '-lossless', 'on', '-Cbypass', 'on'))
    add('SOP and EPH markers', jj2000(
        small, '-lossless', 'on', '-Psop', 'on', '-Peph', 'on'))
    add('packet headers in PPM', jj2000(
        small, '-rate', '3', '-pph_main', 'on', '-Psop', 'on', '-Peph', 'on',
        '-tiles', '16', '24', '-Alayers', '0.5 +2 1 +3'), exact=False)
    add('packet headers in PPT', jj2000(
        small, '-lossless', 'on', '-pph_tile', 'on', '-tiles', '16', '16'))
    add('tile-parts', jj2000(
        large, '-lossless', 'on', '-tiles', '32', '32', '-tile_parts', '2'))
    add('reference grid offsets', jj2000(
        large, '-lossless', 'on', '-ref', '5', '7', '-tref', '2', '3',
        '-tiles', '33', '29'))
    add('region of interest', jj2000(
        small, '-rate', '2', '-Rroi', 'R 5 10 16 20'), exact=False)
    add('region of interest, lossless', jj2000(
        small, '-lossless', 'on', '-Rroi', 'R 5 6 12 14'))
    add('expounded quantization', jj2000(
        small, '-rate', '3', '-Qtype', 'expounded', '-Qguard_bits', '1'),
        exact=False)
    add('eight wavelet levels', jj2000(large, '-lossless', 'on', '-Wlev', '8'))
    add('no wavelet', jj2000(small, '-lossless', 'on', '-Wlev', '0'))
    add('5-3 cut short', jj2000(
        small, '-rate', '2', '-Ffilters', 'w5x3', '-Qtype', 'reversible'),
        exact=False)

    # Hand-made: chroma at half size, the same as sYCC, a palette, channel
    # definitions.
    ycc = small.convert('YCbCr')
    y, cb, cr = ycc.split()
    half = (cb.size[0] // 2, cb.size[1] // 2)
    cb = cb.resize(half)
    cr = cr.resize(half)
    width, height = small.size
    codestream = subsampled(y, cb, cr)
    raw = bytearray()
    rgb = bytearray()
    for row in range(height):
        for col in range(width):
            values = (y.getpixel((col, row)), cb.getpixel((col // 2, row // 2)),
                      cr.getpixel((col // 2, row // 2)))
            raw += bytes(values)
            luma, blue, red = values[0], values[1] - 128, values[2] - 128

            def clip(v):
                return max(0, min(255, math.floor(v + 0.5)))

            rgb += bytes([clip(luma + 1.402 * red),
                          clip(luma - 0.344136 * blue - 0.714136 * red),
                          clip(luma + 1.772 * blue)])
    add('chroma at half size', codestream,
        expected=((width, height), 3, bytes(raw)))
    add('sYCC, chroma at half size',
        jp2(codestream, height, width, 3, colour(18)),
        expected=((width, height), 3, bytes(rgb)))

    indices = Image.new('L', small.size)
    indices.putdata([(x // 4 + y // 5) % 12 for y in range(height)
                     for x in range(width)])
    entries = [(20 * i, 255 - 20 * i, (60 * i) % 256) for i in range(12)]
    palette = box(b'pclr', struct.pack('>HB', 12, 3) + bytes([7, 7, 7])
                  + b''.join(bytes(e) for e in entries))
    mapping = box(b'cmap', b''.join(struct.pack('>HBB', 0, 1, column)
                                    for column in range(3)))
    pixels = b''.join(bytes(entries[v]) for v in indices.get_flattened_data())
    add('palette', jp2(openjpeg(indices, irreversible=False, no_jp2=True),
                       height, width, 1, colour(16), palette, mapping),
        expected=((width, height), 3, pixels))

    reversed_order = box(b'cdef', struct.pack('>H', 3) + b''.join(
        struct.pack('>HHH', channel, 0, 3 - channel) for channel in range(3)))
    straight = small.tobytes()
    swapped = b''.join(straight[i:i + 3][::-1]
                       for i in range(0, len(straight), 3))
    add('channel definitions', jp2(
        openjpeg(small, irreversible=False, no_jp2=True), height, width, 3,
        colour(16), reversed_order), expected=((width, height), 3, swapped))

    out = ['// Made by tool/make_jpeg2000_fixtures.py: JPEG 2000 images from',
           '// OpenJPEG and JJ2000, with the pixels OpenJPEG decodes them to.',
           '',
           'final class Jpeg2000Fixture {',
           '  const Jpeg2000Fixture(this.name, this.image, this.width,'
           ' this.height,',
           '      this.channels, this.expected, {required this.exact});',
           '',
           '  final String name;',
           '',
           '  /// The file, in base64.',
           '  final String image;',
           '',
           '  final int width;',
           '',
           '  final int height;',
           '',
           '  final int channels;',
           '',
           '  /// The SHA-256 of the pixels when [exact], else the pixels in'
           ' base64,',
           '  /// which a lossy image may miss by one.',
           '  final String expected;',
           '',
           '  final bool exact;',
           '}',
           '',
           'const jpeg2000Fixtures = [']
    for name, data, (width, height), channels, pixels, exact in fixtures:
        expected = (hashlib.sha256(pixels).hexdigest() if exact
                    else base64.b64encode(pixels).decode())
        out.append('  Jpeg2000Fixture(')
        out.append(f"    '{name}',")
        encoded = base64.b64encode(data).decode()
        for i in range(0, len(encoded), 72):
            out.append(f"    '{encoded[i:i + 72]}'")
        out[-1] += ','
        out.append(f'    {width},')
        out.append(f'    {height},')
        out.append(f'    {channels},')
        for i in range(0, len(expected), 72):
            out.append(f"    '{expected[i:i + 72]}'")
        out[-1] += ','
        out.append(f'    exact: {"true" if exact else "false"},')
        out.append('  ),')
    out.append('];')
    with open('test/jpeg2000_fixtures.dart', 'w', newline='\n') as f:
        f.write('\n'.join(out) + '\n')
    subprocess.run(['dart', 'format', 'test/jpeg2000_fixtures.dart'],
                   check=True, capture_output=True, shell=os.name == 'nt')
    print(f'{len(fixtures)} fixtures')


if __name__ == '__main__':
    main()
