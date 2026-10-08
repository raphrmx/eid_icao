"""Makes photos of made-up documents, their MRZ the truth beside them: the
fixtures of test/recognizer_test.dart, and as many more as wanted to
measure the recognizer.

    python3 tool/mrz/make_test_images.py OCRB.otf out/ 200 [seed]

Each document gets a background, printed text above its zone, then the
camera's doing: perspective, blur, uneven light, noise and compression.
Writes out/NNN.pgm and out/NNN.txt.
"""

import io
import math
import os
import random
import sys

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

FILLER = '<'
NAMES = ['SPECIMEN', 'ERIKSSON', 'DUPONT', 'VAN DER BERG', 'MULLER',
         'OCONNOR', 'NGUYEN', 'GARCIA LOPEZ', 'JANSSENS', 'PEETERS']
GIVEN = ['ANNA MARIA', 'ALICE', 'JEAN PIERRE', 'MOHAMED', 'SOFIE',
         'LUC', 'MARIE CLAIRE', 'TOM', 'ZOE', 'KAROLINA']
STATES = ['BEL', 'UTO', 'D', 'FRA', 'NLD', 'LUX', 'ITA', 'ESP', 'POL']


def check(field):
    total = 0
    for i, c in enumerate(field):
        if c.isdigit():
            v = int(c)
        elif c.isalpha():
            v = ord(c) - 55
        else:
            v = 0
        total += v * (7, 3, 1)[i % 3]
    return str(total % 10)


def pad(text, n):
    return (text + FILLER * n)[:n]


def names(rng, n):
    last = rng.choice(NAMES).replace(' ', FILLER)
    first = rng.choice(GIVEN).replace(' ', FILLER)
    return pad(last + FILLER * 2 + first, n)


def date(rng, start, end):
    year = rng.randint(start, end)
    return '%02d%02d%02d' % (year % 100, rng.randint(1, 12), rng.randint(1, 28))


def alnum(rng, n):
    chars = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    return ''.join(rng.choice(chars) for _ in range(n))


def td1(rng):
    state = pad(rng.choice(STATES), 3)
    birth = date(rng, 1940, 2015)
    expiry = date(rng, 2026, 2036)
    sex = rng.choice('MF<')
    if rng.random() < 0.4:
        # A Belgian card: twelve digits, the last three overflowing.
        number = ''.join(rng.choice('0123456789') for _ in range(12))
        first_part = number[:9] + FILLER
        optional = pad(number[9:] + check(number), 15)
    else:
        number = alnum(rng, 9)
        first_part = number + check(number)
        optional = pad(alnum(rng, rng.randint(0, 8)), 15)
    line1 = 'I' + rng.choice('D<') + state + first_part + optional
    optional2 = pad(''.join(rng.choice('0123456789') for _ in range(
        rng.choice([0, 11]))), 11)
    nationality = pad(rng.choice(STATES), 3)
    head = (line1[5:30] + birth + check(birth) + expiry + check(expiry)
            + optional2)
    line2 = (birth + check(birth) + sex + expiry + check(expiry) + nationality
             + optional2)
    line2 += check(head)
    line3 = names(rng, 30)
    return [line1, line2, line3]


def td3(rng):
    state = pad(rng.choice(STATES), 3)
    line1 = 'P' + FILLER + state + names(rng, 39)
    number = alnum(rng, 9)
    birth = date(rng, 1940, 2015)
    expiry = date(rng, 2026, 2036)
    personal = pad(alnum(rng, rng.choice([0, 9, 14])), 14)
    personal_check = FILLER if personal == FILLER * 14 else check(personal)
    nationality = pad(rng.choice(STATES), 3)
    line2 = (number + check(number) + nationality + birth + check(birth)
             + rng.choice('MF<') + expiry + check(expiry) + personal
             + personal_check)
    composite = line2[0:10] + line2[13:20] + line2[21:43]
    return [line1, line2 + check(composite)]


def td2(rng):
    state = pad(rng.choice(STATES), 3)
    line1 = 'I' + FILLER + state + names(rng, 31)
    number = alnum(rng, 9)
    birth = date(rng, 1940, 2015)
    expiry = date(rng, 2026, 2036)
    nationality = pad(rng.choice(STATES), 3)
    line2 = (number + check(number) + nationality + birth + check(birth)
             + rng.choice('MF<') + expiry + check(expiry)
             + pad(alnum(rng, rng.randint(0, 7)), 7))
    composite = line2[0:10] + line2[13:20] + line2[21:35]
    return [line1, line2 + check(composite)]


def document(rng, ocrb_path, lines):
    """The document flat, upright, the zone at its foot."""
    em = 64
    face = ImageFont.truetype(ocrb_path, em)
    advance = face.getlength('H')
    n = len(lines[0])
    width = int(advance * n + em * 1.6)
    spacing = em * rng.uniform(1.05, 1.3)
    zone = spacing * len(lines)
    height = int(width * (0.63 if n == 30 else 0.7))
    tone = rng.randint(200, 250)
    card = Image.new('L', (width, height), tone)
    draw = ImageDraw.Draw(card)
    # A guilloche: fine waves across the card.
    for k in range(rng.randint(10, 40)):
        amplitude = rng.uniform(5, 40)
        period = rng.uniform(80, 400)
        phase = rng.uniform(0, 6.3)
        y0 = rng.uniform(0, height)
        shade = tone - rng.randint(10, 60)
        points = [(x, y0 + amplitude * math.sin(x / period * 6.28 + phase))
                  for x in range(0, width, 6)]
        draw.line(points, fill=shade, width=rng.randint(1, 3))
    # A photo and some printed fields above the zone.
    top = height - zone - em
    draw.rectangle([em * 0.6, em * 0.8, width * 0.3, top - em * 0.4],
                   fill=rng.randint(60, 180))
    small = ImageFont.truetype(ocrb_path, int(em * rng.uniform(0.45, 0.8)))
    y = em * 0.8
    while y < top - em:
        word = ''.join(rng.choice('ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 /.')
                       for _ in range(rng.randint(5, 25)))
        draw.text((width * 0.34, y), word, font=small,
                  fill=rng.randint(0, 90))
        y += em * rng.uniform(0.9, 1.4)
    ink = rng.randint(0, 70)
    for i, line in enumerate(lines):
        draw.text((em * 0.8, height - zone - em * 0.25 + i * spacing), line,
                  font=face, fill=ink)
    return card, advance


def camera(rng, card, advance, nprng):
    """The card as a camera sees it."""
    # Bolder or thinner print.
    weight = rng.choice([0, 0, 0, 1, 2, -1])
    if weight > 0:
        card = card.filter(ImageFilter.MinFilter(weight * 2 + 1))
    elif weight < 0:
        card = card.filter(ImageFilter.MaxFilter(3))
    w, h = card.size
    # The pitch the camera gives the zone, and some table around the card.
    pitch = rng.uniform(11, 34)
    scale = pitch / advance
    margin = rng.uniform(0.02, 0.25)
    out_w = int(w * scale * (1 + 2 * margin))
    out_h = int(h * scale * (1 + 2 * margin))
    tilt = rng.uniform(0, 0.12)
    angle = math.radians(rng.uniform(-7, 7))
    # Corners of the card in the output, then the perspective that maps
    # output pixels back onto the card.
    cx, cy = out_w / 2, out_h / 2
    hw, hh = w * scale / 2, h * scale / 2
    corners = []
    for sx, sy in [(-1, -1), (1, -1), (1, 1), (-1, 1)]:
        x = sx * hw * (1 + rng.uniform(-tilt, tilt))
        y = sy * hh * (1 + rng.uniform(-tilt, tilt))
        corners.append((cx + x * math.cos(angle) - y * math.sin(angle),
                        cy + x * math.sin(angle) + y * math.cos(angle)))
    source = [(0, 0), (w, 0), (w, h), (0, h)]
    coeffs = _perspective(corners, source)
    background = rng.randint(20, 120)
    big = card.transform((out_w, out_h), Image.PERSPECTIVE, coeffs,
                         Image.BICUBIC, fillcolor=background)
    image = np.asarray(big).astype(np.float64)
    # Uneven light and a reflection.
    yy, xx = np.mgrid[0:out_h, 0:out_w]
    gx, gy = rng.uniform(-0.5, 0.5), rng.uniform(-0.5, 0.5)
    light = 1 + gx * (xx / out_w - 0.5) + gy * (yy / out_h - 0.5)
    image *= light * rng.uniform(0.6, 1.1)
    if rng.random() < 0.3:
        rx, ry = rng.uniform(0, out_w), rng.uniform(0, out_h)
        radius = rng.uniform(0.1, 0.3) * out_w
        glare = np.exp(-((xx - rx) ** 2 + (yy - ry) ** 2) / radius ** 2)
        image += glare * rng.uniform(40, 120)
    image = Image.fromarray(np.clip(image, 0, 255).astype(np.uint8))
    image = image.filter(ImageFilter.GaussianBlur(rng.uniform(0.3, 1.6)))
    image = np.asarray(image).astype(np.float64)
    image += nprng.normal(0, rng.uniform(1, 9), image.shape)
    image = Image.fromarray(np.clip(image, 0, 255).astype(np.uint8))
    buffer = io.BytesIO()
    image.save(buffer, 'JPEG', quality=rng.randint(35, 90))
    return Image.open(io.BytesIO(buffer.getvalue())).convert('L')


def _perspective(dst, src):
    # The 8 coefficients PIL wants: output (dst) to input (src).
    rows = []
    rhs = []
    for (x, y), (u, v) in zip(dst, src):
        rows.append([x, y, 1, 0, 0, 0, -u * x, -u * y])
        rows.append([0, 0, 0, x, y, 1, -v * x, -v * y])
        rhs += [u, v]
    return np.linalg.solve(np.array(rows, float), np.array(rhs, float))


def main():
    font, out, count = sys.argv[1], sys.argv[2], int(sys.argv[3])
    seed = int(sys.argv[4]) if len(sys.argv) > 4 else 1
    rng = random.Random(seed)
    nprng = np.random.default_rng(seed)
    os.makedirs(out, exist_ok=True)
    for i in range(count):
        maker = rng.choice([td1, td1, td3, td3, td2])
        lines = maker(rng)
        card, advance = document(rng, font, lines)
        image = camera(rng, card, advance, nprng)
        if rng.random() < 0.15:
            image = image.rotate(180)
        image.save(os.path.join(out, '%03d.pgm' % i))
        with open(os.path.join(out, '%03d.txt' % i), 'w') as f:
            f.write('\n'.join(lines))


if __name__ == '__main__':
    main()
