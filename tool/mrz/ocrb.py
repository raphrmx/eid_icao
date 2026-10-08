"""Shared helpers of the tools: the OCR-B renderer and the cell sampler.

The sampler mirrors lib/src/mrz_scanner/glyphs.dart: a template only matches what
the recognizer samples when both are taken the same way.
"""

import numpy as np
from PIL import Image, ImageDraw, ImageFilter, ImageFont

ALPHABET = '0123456789<ABCDEFGHIJKLMNOPQRSTUVWXYZ'

# The cell grid, and the part of the line it covers: one pitch across, from
# 1.25 character heights above the baseline to 0.15 below it.
GRID_WIDTH = 16
GRID_HEIGHT = 24
ABOVE = 1.25
BELOW = 0.15

# The character height the recognizer measures, the median of the tall
# glyphs, letters and digits, in em; the pitch, the advance of OCR-B, in em.
HEIGHT_EM = 0.75
PITCH_EM = 0.723


def font(path, size):
    return ImageFont.truetype(path, size)


def render_line(face, text, size, margin=None, weight=0):
    """Renders [text] dark on white; returns the image and the baseline
    origin of the first cell's centre, in pixels."""
    margin = margin if margin is not None else size
    ascent, descent = face.getmetrics()
    advance = face.getlength('H')
    width = int(margin * 2 + advance * len(text))
    height = int(margin * 2 + ascent + descent)
    image = Image.new('L', (width, height), 255)
    ImageDraw.Draw(image).text((margin, margin), text, font=face, fill=0)
    if weight > 0:
        image = image.filter(ImageFilter.MinFilter(weight * 2 + 1))
    elif weight < 0:
        image = image.filter(ImageFilter.MaxFilter(-weight * 2 + 1))
    return image, (margin + advance / 2, margin + ascent), advance


def integral(gray):
    """The summed area table, one row and column of zeros first."""
    table = np.zeros((gray.shape[0] + 1, gray.shape[1] + 1), np.float64)
    table[1:, 1:] = gray.astype(np.float64).cumsum(0).cumsum(1)
    return table


def _table_at(table, x, y):
    # Bilinear in the table: boxes with fractional edges.
    h, w = table.shape
    x = min(max(x, 0.0), w - 1.0)
    y = min(max(y, 0.0), h - 1.0)
    x0 = min(int(x), w - 2)
    y0 = min(int(y), h - 2)
    fx = x - x0
    fy = y - y0
    top = table[y0, x0] * (1 - fx) + table[y0, x0 + 1] * fx
    bottom = table[y0 + 1, x0] * (1 - fx) + table[y0 + 1, x0 + 1] * fx
    return top * (1 - fy) + bottom * fy


def box_mean(table, cx, cy, half_w, half_h):
    half_w = max(half_w, 0.5)
    half_h = max(half_h, 0.5)
    x0, x1 = cx - half_w, cx + half_w
    y0, y1 = cy - half_h, cy + half_h
    total = (_table_at(table, x1, y1) - _table_at(table, x0, y1)
             - _table_at(table, x1, y0) + _table_at(table, x0, y0))
    return total / ((x1 - x0) * (y1 - y0))


def sample_cell(table, bx, by, pitch, height, angle=0.0, pad=0):
    """The cell whose baseline centre is (bx, by), [pad] extra samples on
    each side, as a (rows, cols) array of mean grey levels."""
    ux, uy = np.cos(angle), np.sin(angle)
    vx, vy = -uy, ux
    step_x = pitch / GRID_WIDTH
    step_y = height * (ABOVE + BELOW) / GRID_HEIGHT
    cols = GRID_WIDTH + 2 * pad
    rows = GRID_HEIGHT + 2 * pad
    out = np.zeros((rows, cols))
    for row in range(rows):
        ly = -ABOVE * height + (row - pad + 0.5) * step_y
        for col in range(cols):
            lx = (col - pad + 0.5 - GRID_WIDTH / 2) * step_x
            px = bx + lx * ux + ly * vx
            py = by + lx * uy + ly * vy
            # The table is offset by one: pixel (x, y) spans [x, x+1).
            out[row, col] = box_mean(table, px, py, step_x / 2, step_y / 2)
    return out


def normalise(cell):
    """Ink positive, zero mean, unit norm; None for a blank cell."""
    v = -cell.astype(np.float64).ravel()
    v -= v.mean()
    norm = np.linalg.norm(v)
    return v / norm if norm > 1e-9 else None
