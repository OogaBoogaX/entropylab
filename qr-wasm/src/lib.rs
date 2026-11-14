//! QR decoding for the Scan QR feature, behind a C ABI like the other
//! EntropyLab WASM crates (no wasm-bindgen).
//!
//! The decoder is quircs 0.10.3. Its measured gaps (qr-eval/RESULTS.md,
//! #1244) are covered by pre-passes: a quiet zone, a 2x upscale for
//! one-pixel modules, and a left-right mirror. Every applicable pass runs and
//! the call refuses when two different payloads appear anywhere in the frame.
//!
//! A decoded payload is a seed: a Standard SeedQR is the mnemonic's numeric
//! form and a CompactSeedQR is the raw entropy. Every decoded payload this
//! module receives is volatile-zeroed; quircs's own internal buffers are not
//! reachable.

use quircs::Quirc;

/// No QR code was located in any pass.
pub const QR_NOT_FOUND: i32 = -1;
/// Codes were located but none decoded.
pub const QR_DECODE_FAILED: i32 = -2;
/// Two or more different payloads decoded: refuse, never pick one.
pub const QR_MULTIPLE_CODES: i32 = -3;
/// The frame, or the frame plus its 16-pixel quiet-zone border, left the
/// accepted limits.
pub const QR_TOO_LARGE: i32 = -4;
/// `out_cap` is smaller than the payload; nothing was written.
pub const QR_OUT_TOO_SMALL: i32 = -5;
/// A null pointer, a side below 21, or a `width * height` overflow.
pub const QR_BAD_ARGS: i32 = -6;

/// The smallest QR symbol is 21x21 modules.
const MIN_DIM: u32 = 21;
/// Largest accepted frame, per side.
const MAX_DIM: u32 = 4096;
/// Largest accepted frame, in pixels.
const MAX_PIXELS: usize = 4_194_304;
/// Quiet zone added by the padded pass, in pixels.
const QUIET: u32 = 16;
/// The upscale pass only runs for frames this small.
const UPSCALE_MAX_DIM: u32 = 640;

/// Allocates `len` zero-filled bytes of linear memory for JS to fill. Pair
/// with `qr_free`. The box owns exactly `len` bytes, so the deallocation
/// layout is reproducible from `len` alone.
#[no_mangle]
pub extern "C" fn qr_alloc(len: usize) -> *mut u8 {
    Box::into_raw(vec![0u8; len].into_boxed_slice()) as *mut u8
}

/// # Safety
/// `ptr` must come from `qr_alloc` and `len` must be exactly the length
/// passed there: the box is reconstructed from `len` alone, so any other
/// length deallocates with the wrong layout.
#[no_mangle]
pub unsafe extern "C" fn qr_free(ptr: *mut u8, len: usize) {
    if ptr.is_null() {
        return;
    }
    // Zero before deallocation: a frame buffer can hold a photographed seed
    // QR, and a payload buffer holds the seed itself.
    wipe(unsafe { std::slice::from_raw_parts_mut(ptr, len) });
    drop(unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len)) });
}

/// ABI version of this module, bumped when the exported surface changes.
#[no_mangle]
pub extern "C" fn qr_version() -> u32 {
    1
}

/// Decodes one 8-bit luminance frame (row-major, `width * height` bytes).
///
/// Returns the payload length on success, else one of the `QR_*` codes.
///
/// # Safety
/// `gray` must point to `width * height` readable bytes and `out` to
/// `out_cap` writable bytes; both must be non-null.
#[no_mangle]
pub unsafe extern "C" fn qr_decode(
    gray: *const u8,
    width: u32,
    height: u32,
    out: *mut u8,
    out_cap: usize,
) -> i32 {
    if gray.is_null() || out.is_null() {
        return QR_BAD_ARGS;
    }
    if width < MIN_DIM || height < MIN_DIM {
        return QR_BAD_ARGS;
    }
    let Some(pixels) = (width as usize).checked_mul(height as usize) else {
        return QR_BAD_ARGS;
    };
    // Every accepted frame must get every pass, so the padded frame has to fit
    // the same limits: a frame too large to pad is refused up front rather
    // than scanned by the first pass alone, where a mirrored second code
    // would go unseen and one payload could be returned.
    let w = width as usize;
    let h = height as usize;
    let pad_w = w + QUIET as usize * 2;
    let pad_h = h + QUIET as usize * 2;
    if pad_w > MAX_DIM as usize || pad_h > MAX_DIM as usize || pixels > MAX_PIXELS || pad_w * pad_h > MAX_PIXELS {
        return QR_TOO_LARGE;
    }
    let input = unsafe { std::slice::from_raw_parts(gray, pixels) };

    let mut found = Found { payloads: Vec::new(), located: 0 };

    // (a) the frame as is.
    scan(input, w, h, &mut found);

    // (b)-(d) work on a frame with a 16-pixel white border; the limits above
    // guarantee it fits.
    let Some(mut padded) = Frame::light(pad_w, pad_h) else {
        return QR_TOO_LARGE;
    };
    for y in 0..h {
        let dst = (y + QUIET as usize) * pad_w + QUIET as usize;
        padded.pixels[dst..dst + w].copy_from_slice(&input[y * w..(y + 1) * w]);
    }

    // (b) the padded frame.
    scan(&padded.pixels, pad_w, pad_h, &mut found);

    // (c) 2x nearest-neighbour upscale, for one-pixel modules.
    if w.max(h) <= UPSCALE_MAX_DIM as usize {
        if let Some(up) = upscale(&padded) {
            scan(&up.pixels, up.width, up.height, &mut found);
        }
    }

    // (d) mirrored left-right.
    if let Some(flipped) = mirror(&padded) {
        scan(&flipped.pixels, flipped.width, flipped.height, &mut found);
    }

    decide(found, out, out_cap)
}

/// Copies the payload into `out`. Writes nothing when `out_cap` is too small.
fn emit(out: *mut u8, out_cap: usize, secret: &Secret) -> i32 {
    if out_cap < secret.0.len() {
        return QR_OUT_TOO_SMALL;
    }
    // Soundness: `qr_decode` checked `out` is non-null and the caller
    // guarantees `out_cap` writable bytes there.
    unsafe { std::ptr::copy_nonoverlapping(secret.0.as_ptr(), out, secret.0.len()) };
    secret.0.len() as i32
}

/// Runs quircs over one frame and adds the distinct payloads it decodes to
/// `found`, deduplicating against everything collected so far.
fn scan(pixels: &[u8], width: usize, height: usize, found: &mut Found) {
    let mut quirc = Quirc::new();
    for code in quirc.identify(width, height, pixels) {
        found.located += 1;
        let Ok(code) = code else { continue };
        let Ok(mut data) = code.decode() else { continue };
        if found.payloads.iter().any(|seen| seen == &data.payload) {
            // A duplicate is dropped here, so wipe it before it goes.
            wipe(data.payload.as_mut_slice());
            continue;
        }
        found.payloads.push(data.payload);
    }
}

/// What the passes over the frame found.
struct Found {
    /// Distinct payloads across all passes, in the order they were decoded.
    payloads: Vec<Vec<u8>>,
    /// Codes located, decodable or not.
    located: usize,
}

impl Drop for Found {
    fn drop(&mut self) {
        for payload in self.payloads.iter_mut() {
            wipe(payload.as_mut_slice());
        }
    }
}

/// Settles the call on everything the passes collected: two or more distinct
/// payloads are refused, exactly one is emitted, and a frame where codes were
/// located but none decoded is a decode failure.
fn decide(mut found: Found, out: *mut u8, out_cap: usize) -> i32 {
    if found.payloads.len() > 1 {
        return QR_MULTIPLE_CODES;
    }
    if found.payloads.len() == 1 {
        let secret = Secret(std::mem::take(&mut found.payloads[0]));
        return emit(out, out_cap, &secret);
    }
    if found.located > 0 {
        QR_DECODE_FAILED
    } else {
        QR_NOT_FOUND
    }
}

/// A decoded payload. A Standard SeedQR is the mnemonic's numeric form and a
/// CompactSeedQR is the raw entropy, so it is volatile-zeroed when it goes
/// out of scope, on every path.
struct Secret(Vec<u8>);

impl Drop for Secret {
    fn drop(&mut self) {
        wipe(self.0.as_mut_slice());
    }
}

/// An owned luminance frame that volatile-zeroes itself before the heap cell
/// is released: a frame can hold a photographed seed QR.
struct Frame {
    pixels: Vec<u8>,
    width: usize,
    height: usize,
}

impl Frame {
    /// A `width` x `height` frame of light (255) pixels, or `None` when the
    /// frame would leave the accepted limits.
    fn light(width: usize, height: usize) -> Option<Frame> {
        let len = width.checked_mul(height)?;
        if len > MAX_PIXELS {
            return None;
        }
        Some(Frame { pixels: vec![255u8; len], width, height })
    }
}

impl Drop for Frame {
    fn drop(&mut self) {
        wipe(self.pixels.as_mut_slice());
    }
}

/// Nearest-neighbour 2x upscale, for codes rendered at one pixel per module.
fn upscale(frame: &Frame) -> Option<Frame> {
    let width = frame.width.checked_mul(2)?;
    let height = frame.height.checked_mul(2)?;
    let mut up = Frame::light(width, height)?;
    for y in 0..frame.height {
        let src = &frame.pixels[y * frame.width..(y + 1) * frame.width];
        for (x, &pixel) in src.iter().enumerate() {
            let top = (y * 2) * width + x * 2;
            up.pixels[top] = pixel;
            up.pixels[top + 1] = pixel;
            up.pixels[top + width] = pixel;
            up.pixels[top + width + 1] = pixel;
        }
    }
    Some(up)
}

/// Left-right mirror, for codes read through a front-facing camera.
fn mirror(frame: &Frame) -> Option<Frame> {
    let mut out = Frame::light(frame.width, frame.height)?;
    for y in 0..frame.height {
        let src = &frame.pixels[y * frame.width..(y + 1) * frame.width];
        let dst = &mut out.pixels[y * frame.width..(y + 1) * frame.width];
        for (x, &pixel) in src.iter().enumerate() {
            dst[frame.width - 1 - x] = pixel;
        }
    }
    Some(out)
}

/// Overwrites `buf` with zeroes. Volatile stores plus a compiler fence, so
/// the wipe cannot be elided as a dead store ahead of deallocation.
fn wipe(buf: &mut [u8]) {
    for byte in buf.iter_mut() {
        // Soundness: `byte` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(byte, 0u8) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use qrcode::bits::Bits;
    use qrcode::types::{Color, EcLevel, Version};
    use qrcode::QrCode;

    /// Renders `code` at `module_px` pixels per module with a `quiet`-module
    /// border: dark 0, light 255.
    fn render(code: &QrCode, module_px: usize, quiet: usize) -> (Vec<u8>, usize, usize) {
        let modules = code.to_colors();
        let n = code.width();
        let side = (n + quiet * 2) * module_px;
        let mut pixels = vec![255u8; side * side];
        for y in 0..n {
            for x in 0..n {
                if modules[y * n + x] != Color::Dark {
                    continue;
                }
                for dy in 0..module_px {
                    for dx in 0..module_px {
                        let px = (quiet + x) * module_px + dx;
                        let py = (quiet + y) * module_px + dy;
                        pixels[py * side + px] = 0;
                    }
                }
            }
        }
        (pixels, side, side)
    }

    fn encode_byte(payload: &[u8]) -> QrCode {
        let mut bits = Bits::new(Version::Normal(4));
        bits.push_byte_data(payload).expect("byte data fits version 4-M");
        // The terminator pads the stream to the version's full data length.
        bits.push_terminator(EcLevel::M).expect("version 4-M has room for the terminator");
        QrCode::with_bits(bits, EcLevel::M).expect("version 4-M encodes")
    }

    fn encode_numeric(payload: &str) -> QrCode {
        let mut bits = Bits::new(Version::Normal(4));
        // qrcode 0.14 takes the numeric payload as ASCII bytes.
        bits.push_numeric_data(payload.as_bytes()).expect("numeric data fits version 4-M");
        bits.push_terminator(EcLevel::M).expect("version 4-M has room for the terminator");
        QrCode::with_bits(bits, EcLevel::M).expect("version 4-M encodes")
    }

    fn hex(text: &str) -> Vec<u8> {
        assert_eq!(text.len() % 2, 0, "hex length");
        (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).expect("hex digit"))
            .collect()
    }

    fn decode_into(pixels: &[u8], width: u32, height: u32, out: &mut [u8]) -> i32 {
        // Soundness: `pixels` is `width * height` bytes and `out` is `out.len()`.
        unsafe { qr_decode(pixels.as_ptr(), width, height, out.as_mut_ptr(), out.len()) }
    }

    fn decode(pixels: &[u8], width: u32, height: u32) -> (i32, Vec<u8>) {
        let mut out = vec![0u8; 4096];
        let code = decode_into(pixels, width, height, &mut out);
        (code, out)
    }

    fn assert_payload(pixels: &[u8], width: usize, height: usize, payload: &[u8]) {
        let (len, out) = decode(pixels, width as u32, height as u32);
        assert_eq!(len, payload.len() as i32, "decode status");
        assert_eq!(&out[..payload.len()], payload, "payload bytes");
    }

    fn blit(canvas: &mut [u8], canvas_width: usize, src: &[u8], w: usize, h: usize, x0: usize, y0: usize) {
        for y in 0..h {
            let dst = (y0 + y) * canvas_width + x0;
            canvas[dst..dst + w].copy_from_slice(&src[y * w..(y + 1) * w]);
        }
    }

    fn mirror_pixels(src: &[u8], w: usize, h: usize) -> Vec<u8> {
        let mut out = vec![0u8; src.len()];
        for y in 0..h {
            for x in 0..w {
                out[y * w + (w - 1 - x)] = src[y * w + x];
            }
        }
        out
    }

    #[test]
    fn decodes_exact_bytes() {
        let cases: Vec<Vec<u8>> = vec![
            vec![0u8; 16],
            hex("0e59dde276009317f1275f1389888078c99368d1e82489b5f629531fc5b6a56e"),
            hex("f55cf587f2543d01090d0ae710bd3b6d"),
            (0x80u8..=0x9f).collect(),
        ];
        for payload in &cases {
            let code = encode_byte(payload);
            let (pixels, w, h) = render(&code, 4, 4);
            assert_payload(&pixels, w, h, payload);
        }

        // A Standard SeedQR is numeric mode: the payload is ASCII digits.
        let digits = "073318950739065415961602009907670428187212261116";
        let code = encode_numeric(digits);
        let (pixels, w, h) = render(&code, 4, 4);
        assert_payload(&pixels, w, h, digits.as_bytes());
    }

    #[test]
    fn decodes_without_a_quiet_zone() {
        let payload = hex("f55cf587f2543d01090d0ae710bd3b6d");
        let code = encode_byte(&payload);
        let (pixels, w, h) = render(&code, 4, 0);
        assert_payload(&pixels, w, h, &payload);
    }

    #[test]
    fn decodes_one_pixel_modules() {
        let payload = hex("f55cf587f2543d01090d0ae710bd3b6d");
        let code = encode_byte(&payload);
        let (pixels, w, h) = render(&code, 1, 4);
        assert_payload(&pixels, w, h, &payload);
    }

    #[test]
    fn decodes_a_mirrored_code() {
        let payload = hex("f55cf587f2543d01090d0ae710bd3b6d");
        let code = encode_byte(&payload);
        let (pixels, w, h) = render(&code, 4, 4);
        let flipped = mirror_pixels(&pixels, w, h);
        assert_payload(&flipped, w, h, &payload);
    }

    #[test]
    fn blank_frame_is_not_found() {
        let pixels = vec![255u8; 640 * 480];
        let (len, _) = decode(&pixels, 640, 480);
        assert_eq!(len, QR_NOT_FOUND);
    }

    #[test]
    fn two_different_codes_are_refused() {
        let a = encode_byte(&hex("f55cf587f2543d01090d0ae710bd3b6d"));
        let b = encode_byte(&hex("0e59dde276009317f1275f1389888078c99368d1e82489b5f629531fc5b6a56e"));
        let (pa, wa, ha) = render(&a, 4, 4);
        let (pb, wb, hb) = render(&b, 4, 4);
        let width = wa + wb;
        let height = ha.max(hb);
        let mut canvas = vec![255u8; width * height];
        blit(&mut canvas, width, &pa, wa, ha, 0, 0);
        blit(&mut canvas, width, &pb, wb, hb, wa, 0);
        let (len, _) = decode(&canvas, width as u32, height as u32);
        assert_eq!(len, QR_MULTIPLE_CODES);
    }

    #[test]
    fn cross_pass_codes_are_refused() {
        // A decodes as is; B only decodes once the frame is mirrored. The two
        // payloads appear in different passes, so the call must still refuse.
        let a = encode_byte(&hex("f55cf587f2543d01090d0ae710bd3b6d"));
        let b = encode_byte(&hex("0e59dde276009317f1275f1389888078c99368d1e82489b5f629531fc5b6a56e"));
        let (pa, wa, ha) = render(&a, 4, 4);
        let (pb, wb, hb) = render(&b, 4, 4);
        let pb = mirror_pixels(&pb, wb, hb);
        let width = wa + wb;
        let height = ha.max(hb);
        let mut canvas = vec![255u8; width * height];
        blit(&mut canvas, width, &pa, wa, ha, 0, 0);
        blit(&mut canvas, width, &pb, wb, hb, wa, 0);
        let (len, _) = decode(&canvas, width as u32, height as u32);
        assert_eq!(len, QR_MULTIPLE_CODES);
    }

    #[test]
    fn cross_pass_quiet_zone_codes_are_refused() {
        // A carries its own quiet zone; B is flush against the right edge and
        // only decodes once the padded pass adds a border. The two payloads
        // appear in different passes, so the call must still refuse.
        let a = encode_byte(&hex("f55cf587f2543d01090d0ae710bd3b6d"));
        let b = encode_byte(&hex("0e59dde276009317f1275f1389888078c99368d1e82489b5f629531fc5b6a56e"));
        let (pa, wa, ha) = render(&a, 4, 4);
        let (pb, wb, hb) = render(&b, 4, 0);
        let width = wa + wb;
        let height = ha.max(hb);
        let mut canvas = vec![255u8; width * height];
        blit(&mut canvas, width, &pa, wa, ha, 0, 0);
        blit(&mut canvas, width, &pb, wb, hb, wa, 0);
        let (len, _) = decode(&canvas, width as u32, height as u32);
        assert_eq!(len, QR_MULTIPLE_CODES);
    }

    #[test]
    fn duplicate_codes_count_once() {
        let payload = hex("f55cf587f2543d01090d0ae710bd3b6d");
        let code = encode_byte(&payload);
        let (pixels, w, h) = render(&code, 4, 4);
        let width = w * 2;
        let mut canvas = vec![255u8; width * h];
        blit(&mut canvas, width, &pixels, w, h, 0, 0);
        blit(&mut canvas, width, &pixels, w, h, w, 0);
        assert_payload(&canvas, width, h, &payload);
    }

    #[test]
    fn oversized_frame_is_too_large() {
        let pixels = vec![255u8; 5000 * 21];
        let mut out = vec![0u8; 64];
        assert_eq!(decode_into(&pixels, 5000, 21, &mut out), QR_TOO_LARGE);
    }

    #[test]
    fn a_frame_too_large_to_pad_is_refused_so_every_pass_runs() {
        // 2048x2048 is within MAX_PIXELS, but its padded frame (2080x2080) is
        // not: it is refused instead of being scanned by the first pass alone.
        let big = vec![255u8; 2048 * 2048];
        let mut out = vec![0u8; 64];
        assert_eq!(decode_into(&big, 2048, 2048, &mut out), QR_TOO_LARGE);
        // A side whose padded width passes MAX_DIM is refused too.
        let wide = vec![255u8; 4080 * 21];
        assert_eq!(decode_into(&wide, 4080, 21, &mut out), QR_TOO_LARGE);
        // 2000x2000 pads to 2032x2032, inside the limits: accepted and scanned.
        let fits = vec![255u8; 2000 * 2000];
        assert_eq!(decode_into(&fits, 2000, 2000, &mut out), QR_NOT_FOUND);
    }

    #[test]
    fn tiny_frame_is_bad_args() {
        let pixels = vec![255u8; 20 * 20];
        let mut out = vec![0u8; 64];
        assert_eq!(decode_into(&pixels, 20, 20, &mut out), QR_BAD_ARGS);
    }

    #[test]
    fn null_input_is_bad_args() {
        let mut out = vec![0u8; 64];
        // Soundness: a null `gray` is refused before it is read.
        let code = unsafe { qr_decode(std::ptr::null(), 100, 100, out.as_mut_ptr(), out.len()) };
        assert_eq!(code, QR_BAD_ARGS);
    }

    #[test]
    fn alloc_free_round_trip() {
        let ptr = qr_alloc(1000);
        assert!(!ptr.is_null(), "qr_alloc returns memory");
        // Soundness: `qr_alloc(1000)` owns 1000 writable bytes.
        let buf = unsafe { std::slice::from_raw_parts_mut(ptr, 1000) };
        assert!(buf.iter().all(|&b| b == 0), "qr_alloc zero-fills");
        for byte in buf.iter_mut() {
            *byte = 0xaa;
        }
        // Soundness: `ptr` came from `qr_alloc(1000)`.
        unsafe { qr_free(ptr, 1000) };
        // A null pointer with a zero length is a no-op, not a crash.
        unsafe { qr_free(std::ptr::null_mut(), 0) };
    }

    #[test]
    fn small_output_is_refused_and_untouched() {
        let payload = vec![0u8; 16];
        let code = encode_byte(&payload);
        let (pixels, w, h) = render(&code, 4, 4);
        let mut out = vec![0xaau8; 3];
        assert_eq!(decode_into(&pixels, w as u32, h as u32, &mut out), QR_OUT_TOO_SMALL);
        assert_eq!(out, vec![0xaau8; 3]);
    }

    #[test]
    fn noise_never_decodes() {
        let mut state = 0x2545_f491_4f6c_dd1du64;
        for _ in 0..200 {
            let mut pixels = vec![0u8; 64 * 64];
            for byte in pixels.iter_mut() {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *byte = (state >> 24) as u8;
            }
            let (len, _) = decode(&pixels, 64, 64);
            assert!(
                len == QR_NOT_FOUND || len == QR_DECODE_FAILED,
                "a noise frame returned {len}"
            );
        }
    }

    #[test]
    fn wipe_zeroes_every_byte() {
        let mut buf = vec![0xffu8; 64];
        wipe(&mut buf);
        assert_eq!(buf, vec![0u8; 64]);
    }
}
