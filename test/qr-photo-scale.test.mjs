// The photo fallback must fit a frame to the decoder's caps *after* its
// quiet-zone padding. qr-wasm pads every frame by QUIET_ZONE pixels a side
// and refuses anything whose padded frame exceeds MAX_DIM or MAX_PIXELS
// (qr-wasm/src/lib.rs), so clamping to the raw pixel cap alone leaves no
// room for the padding and refuses every ordinary phone photo. The lost
// frame is then reported as "No QR code was found in this photo", not as a
// size refusal, which is why the existing mocked-decoder tests never saw it.
//
// The expectations below come from the decoder's stated limits (4096 per
// side, 4_194_304 pixels, 16 px quiet zone a side), not from the helper.
import test from "node:test";
import assert from "node:assert/strict";
import { photoFrameSize } from "../src/js/qr-scanner.js";

const QUIET_ZONE = 16;
const MAX_IMAGE_SIDE = 4096;
const MAX_IMAGE_PIXELS = 4_194_304;

const assertFits = (sourceWidth, sourceHeight) => {
  const { width, height } = photoFrameSize(sourceWidth, sourceHeight);
  assert.ok(width >= 1 && height >= 1, `${sourceWidth}x${sourceHeight}: a frame is kept`);
  assert.ok(width <= MAX_IMAGE_SIDE && height <= MAX_IMAGE_SIDE, `${sourceWidth}x${sourceHeight}: side within ${MAX_IMAGE_SIDE}`);
  const paddedWidth = width + QUIET_ZONE * 2, paddedHeight = height + QUIET_ZONE * 2;
  assert.ok(paddedWidth <= MAX_IMAGE_SIDE && paddedHeight <= MAX_IMAGE_SIDE, `${sourceWidth}x${sourceHeight}: padded side within ${MAX_IMAGE_SIDE}`);
  assert.ok(paddedWidth * paddedHeight <= MAX_IMAGE_PIXELS, `${sourceWidth}x${sourceHeight}: padded pixels within ${MAX_IMAGE_PIXELS} (${paddedWidth}x${paddedHeight})`);
  return { width, height };
};

test("ordinary phone photos fit the decoder once its quiet zone is reserved", () => {
  // 12 MP frames in both orientations, and the largest square under the cap.
  for (const [width, height] of [[3024, 4032], [4032, 3024], [4032, 4032], [4096, 4096], [4096, 3072]]) {
    assertFits(width, height);
  }
});

test("a frame already inside the budget keeps its size", () => {
  // 2016 + 32 = 2048 a side, exactly MAX_PIXELS when square, and 2048x1536.
  assert.deepEqual(assertFits(2016, 2016), { width: 2016, height: 2016 });
  assert.deepEqual(assertFits(2048, 1536), { width: 2048, height: 1536 });
  assert.deepEqual(assertFits(800, 800), { width: 800, height: 800 });
});

test("one pixel over the largest padded square is scaled down, not passed on", () => {
  // The old clamp left this at full size, where the pad then overflowed.
  const { width } = assertFits(2017, 2017);
  assert.ok(width < 2017, "2017x2017 must be reduced to leave pad room");
  const naivePadded = (2017 + QUIET_ZONE * 2) ** 2;
  assert.ok(naivePadded > MAX_IMAGE_PIXELS, `fixture: ${naivePadded} is over the cap`);
});

test("extreme aspect ratios still produce a padded frame", () => {
  for (const [width, height] of [[100_000, 100], [100, 100_000], [4096, 21]]) {
    assertFits(width, height);
  }
});

test("a zero dimension cannot produce a zero frame", () => {
  assert.deepEqual(photoFrameSize(0, 0), { width: 1, height: 1 });
});
