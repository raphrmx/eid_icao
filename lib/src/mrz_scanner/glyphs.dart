import 'dart:math' as math;
import 'dart:typed_data';

import 'package:eid_icao/src/mrz_scanner/layout.dart';
import 'package:eid_icao/src/mrz_scanner/ocrb_templates.dart';
import 'package:eid_icao/src/mrz_scanner/plane.dart';

/// The samples a cell may shift by each way, to meet its template.
const int _slack = 1;

/// The samples of a cell.
const int cellSize = templateWidth * templateHeight;

/// The templates, zero mean and unit length, one after the other.
final Float32List _templates = () {
  final out = Float32List(ocrbTemplates.length * cellSize);
  for (var t = 0; t < ocrbTemplates.length; t++) {
    final template = ocrbTemplates[t];
    var mean = 0.0;
    for (final v in template) {
      mean += v;
    }
    mean /= cellSize;
    var norm = 0.0;
    for (final v in template) {
      norm += (v - mean) * (v - mean);
    }
    norm = math.sqrt(norm);
    for (var i = 0; i < cellSize; i++) {
      out[t * cellSize + i] = (template[i] - mean) / norm;
    }
  }
  return out;
}();

/// A cell of the zone as sampled: its ink, aligned on the template it
/// meets best, and its correlation with every template.
final class CellSample {
  CellSample._(this.window, this.correlations);

  /// The ink of the cell, [templateWidth] by [templateHeight] row by row,
  /// zero mean and unit length; all zero for a blank cell.
  final Float32List window;

  /// The best correlation with the template of each character of
  /// [ocrbAlphabet] over small shifts, from -1 to 1.
  final Float32List correlations;
}

/// The cell at [cell] in [plane], sampled.
CellSample sampleCell(GreyPlane plane, CellGeometry cell) {
  const cols = templateWidth + 2 * _slack;
  const rows = templateHeight + 2 * _slack;
  final ux = math.cos(cell.angle);
  final uy = math.sin(cell.angle);
  final stepX = cell.pitch / templateWidth;
  final stepY = cell.height * (cellAbove + cellBelow) / templateHeight;
  final grid = Float32List(cols * rows);
  for (var row = 0; row < rows; row++) {
    final ly = -cellAbove * cell.height + (row - _slack + 0.5) * stepY;
    for (var col = 0; col < cols; col++) {
      final lx = (col - _slack + 0.5 - templateWidth / 2) * stepX;
      // Along the line, then down square to it.
      final px = cell.x + lx * ux - ly * uy;
      final py = cell.y + lx * uy + ly * ux;
      // Ink positive.
      grid[row * cols + col] = -plane.boxMean(px, py, stepX / 2, stepY / 2);
    }
  }

  final count = ocrbTemplates.length;
  final correlations = Float32List(count)..fillRange(0, count, -1);
  final window = Float32List(cellSize);
  final best = Float32List(cellSize);
  var bestScore = -2.0;
  for (var dy = 0; dy <= 2 * _slack; dy++) {
    for (var dx = 0; dx <= 2 * _slack; dx++) {
      var mean = 0.0;
      for (var r = 0; r < templateHeight; r++) {
        final from = (r + dy) * cols + dx;
        for (var c = 0; c < templateWidth; c++) {
          final v = grid[from + c];
          window[r * templateWidth + c] = v;
          mean += v;
        }
      }
      mean /= cellSize;
      var norm = 0.0;
      for (var i = 0; i < cellSize; i++) {
        final v = window[i] - mean;
        window[i] = v;
        norm += v * v;
      }
      if (norm < 1e-6) continue;
      final scale = 1 / math.sqrt(norm);
      for (var i = 0; i < cellSize; i++) {
        window[i] *= scale;
      }
      var top = -2.0;
      for (var t = 0; t < count; t++) {
        var dot = 0.0;
        final base = t * cellSize;
        for (var i = 0; i < cellSize; i++) {
          dot += window[i] * _templates[base + i];
        }
        if (dot > correlations[t]) correlations[t] = dot;
        if (dot > top) top = dot;
      }
      if (top > bestScore) {
        bestScore = top;
        best.setAll(0, window);
      }
    }
  }
  if (bestScore < -1) correlations.fillRange(0, count, 0);
  return CellSample._(best, correlations);
}
