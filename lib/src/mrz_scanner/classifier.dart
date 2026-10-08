import 'dart:math' as math;
import 'dart:typed_data';

import 'package:eid_icao/src/mrz_scanner/glyph_model.dart';
import 'package:eid_icao/src/mrz_scanner/glyphs.dart';
import 'package:eid_icao/src/mrz_scanner/ocrb_templates.dart';

/// How likely the cell [sample] holds each character of [ocrbAlphabet], as
/// natural logarithms: 0 for certain, more negative for less likely.
///
/// A small network trained on cells of photographed documents weighs the
/// ink of the cell and its correlation with each template: it parts the
/// characters a template alone confuses, as 0 and O.
Float32List classify(CellSample sample) {
  const count = ocrbAlphabet.length;
  const inputs = cellSize + count;
  final x = Float32List(inputs)..setAll(0, sample.window);
  for (var i = 0; i < count; i++) {
    x[cellSize + i] = sample.correlations[i] * modelCorrelationScale;
  }
  final hidden = Float32List(modelHidden);
  for (var j = 0; j < modelHidden; j++) {
    // Integer weights first, scaled once per neuron.
    var dot = 0.0;
    final base = j * inputs;
    for (var i = 0; i < inputs; i++) {
      dot += modelW1Weights[base + i] * x[i];
    }
    final value = dot * modelW1Scales[j] + modelB1[j];
    hidden[j] = value > 0 ? value : 0;
  }
  final logits = Float32List(count);
  var top = double.negativeInfinity;
  for (var k = 0; k < count; k++) {
    var dot = 0.0;
    final base = k * modelHidden;
    for (var j = 0; j < modelHidden; j++) {
      dot += modelW2Weights[base + j] * hidden[j];
    }
    final value = dot * modelW2Scales[k] + modelB2[k];
    logits[k] = value;
    if (value > top) top = value;
  }
  var total = 0.0;
  for (var k = 0; k < count; k++) {
    total += math.exp(logits[k] - top);
  }
  final log = top + math.log(total);
  for (var k = 0; k < count; k++) {
    logits[k] -= log;
  }
  return logits;
}
