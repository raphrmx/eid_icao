// This software makes use of the Schema from ISO/IEC 39794-5 within
// modifications permitted in the relevant ISO/IEC standard. Please reproduce
// this note if possible.
//
// Use of ISO/IEC copyright in this Schema is licensed for the purpose of
// developing, implementing, and using software based on this Schema, subject
// to the following conditions:
//
// * Software developed from this Schema must retain the Copyright Notice,
//   this list of conditions and the disclaimer below ("Disclaimer").
//
// * Neither the name or logo of ISO or of IEC, nor the names of specific
//   contributors, may be used to endorse or promote software derived from
//   this Schema without specific prior written permission.
//
// * The software developer shall attribute the Schema to ISO/IEC and
//   identify the ISO/IEC standard from which it is taken.
//
// The Disclaimer is:
// THE SCHEMA ON WHICH THIS SOFTWARE IS BASED IS PROVIDED BY THE COPYRIGHT
// HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES,
// INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
// AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
// THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
// NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
// DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
// THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
// (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
// THE CODE COMPONENTS, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

import 'dart:typed_data';

import 'package:eid_icao/src/image.dart';
import 'package:eid_icao/src/tlv.dart';

/// The faces of an ISO/IEC 39794-5 FaceImageDataBlock, from its [fields].
/// Implicit tags: representationBlocks `[1]`, each
/// imageRepresentation `[1]`, base `[0]`, imageRepresentation2DBlock `[0]`,
/// whose representationData2D `[0]` holds the image.
List<IcaoImage> faces39794(List<Tlv> fields) {
  Tlv? find(List<Tlv> elements, int tag) {
    for (final element in elements) {
      if (element.tag == tag) return element;
    }
    return null;
  }

  final blocks = find(fields, 0xA1);
  if (blocks == null) throw const FormatException('No representation blocks');
  final faces = <IcaoImage>[];
  for (final representation in blocks.children) {
    final image = find(representation.children, 0xA1);
    final base = image == null ? null : find(image.children, 0xA0);
    final twoD = base == null ? null : find(base.children, 0xA0);
    if (twoD == null) continue;
    final data = find(twoD.children, 0x80);
    if (data == null) continue;
    var width = 0;
    var height = 0;
    final information = find(twoD.children, 0xA1);
    final size = information == null ? null : find(information.children, 0xA7);
    if (size != null) {
      width = find(size.children, 0x80)?.smallInteger ?? 0;
      height = find(size.children, 0x81)?.smallInteger ?? 0;
    }
    faces.add(sniffImage(
      Uint8List.fromList(data.value),
      width: width > 0 ? width : null,
      height: height > 0 ? height : null,
    ));
  }
  return faces;
}
