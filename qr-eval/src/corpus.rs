//! Synthetic corpus: payloads encoded with `qrcode`, then degraded.

use qrcode::bits::Bits;
use qrcode::types::{Color, EcLevel, Version};
use qrcode::QrCode;

use crate::prng::Rng;
use crate::raster::Raster;

pub struct Case {
    pub name: String,
    pub payload_id: String,
    pub degradation: String,
    pub ec: String,
    pub raster: Raster,
    pub expected: Option<Vec<u8>>,
}

pub struct TwoCodeCase {
    pub name: String,
    pub raster: Raster,
    pub expected: Vec<Vec<u8>>,
}

pub struct FlipCase {
    pub group: String,
    pub name: String,
    pub raster: Raster,
    pub expected: Vec<u8>,
}

pub struct RobustCase {
    pub name: String,
    pub raster: Raster,
}

pub enum Segment {
    Numeric(Vec<u8>),
    Alphanumeric(Vec<u8>),
    Byte(Vec<u8>),
    Eci(u32),
    Kanji(Vec<u8>),
}

pub struct Payload {
    pub number: u32,
    pub id: &'static str,
    pub segments: Vec<Segment>,
    pub expected: Vec<u8>,
    pub ec_levels: Vec<EcLevel>,
}

pub fn payloads() -> Vec<Payload> {
    let mut out = Vec::new();

    let p1 = b"073318950739065415961602009907670428187212261116".to_vec();
    out.push(Payload {
        number: 1,
        id: "P1 std12-leading-zero",
        segments: vec![Segment::Numeric(p1.clone())],
        expected: p1,
        ec_levels: vec![EcLevel::L, EcLevel::M, EcLevel::H],
    });

    let p2 = b"011513251154012711900771041507421289190620080870026613431420201617920614089619290300152408010643".to_vec();
    out.push(Payload {
        number: 2,
        id: "P2 std24",
        segments: vec![Segment::Numeric(p2.clone())],
        expected: p2,
        ec_levels: vec![EcLevel::L, EcLevel::M],
    });

    let mut p3 = Vec::new();
    for _ in 0..11 {
        p3.extend_from_slice(b"0000");
    }
    p3.extend_from_slice(b"0003");
    out.push(Payload {
        number: 3,
        id: "P3 std12-index-zero",
        segments: vec![Segment::Numeric(p3.clone())],
        expected: p3,
        ec_levels: vec![EcLevel::L, EcLevel::M],
    });

    let p4 = vec![0u8; 16];
    out.push(Payload {
        number: 4,
        id: "P4 compact16-all-nul",
        segments: vec![Segment::Byte(p4.clone())],
        expected: p4,
        ec_levels: vec![EcLevel::L, EcLevel::M, EcLevel::H],
    });

    let p5 = hex("0e59dde276009317f1275f1389888078c99368d1e82489b5f629531fc5b6a56e");
    out.push(Payload {
        number: 5,
        id: "P5 compact32-nul",
        segments: vec![Segment::Byte(p5.clone())],
        expected: p5,
        ec_levels: vec![EcLevel::L, EcLevel::M, EcLevel::H],
    });

    let p6 = hex("f55cf587f2543d01090d0ae710bd3b6d");
    out.push(Payload {
        number: 6,
        id: "P6 compact16-crlf",
        segments: vec![Segment::Byte(p6.clone())],
        expected: p6,
        ec_levels: vec![EcLevel::L, EcLevel::M],
    });

    let p7: Vec<u8> = (0x80..=0x9f).collect();
    out.push(Payload {
        number: 7,
        id: "P7 high-bytes",
        segments: vec![Segment::Byte(p7.clone())],
        expected: p7,
        ec_levels: vec![EcLevel::L, EcLevel::M],
    });

    let p8 = b"forum undo fragile fade shy sign arrest garment culture tube off merit".to_vec();
    out.push(Payload {
        number: 8,
        id: "P8 words",
        segments: vec![Segment::Byte(p8.clone())],
        expected: p8,
        ec_levels: vec![EcLevel::L, EcLevel::M],
    });

    let p9 = b"KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn".to_vec();
    out.push(Payload {
        number: 9,
        id: "P9 wif",
        segments: vec![Segment::Byte(p9.clone())],
        expected: p9,
        ec_levels: vec![EcLevel::L, EcLevel::M],
    });

    let mut rng = Rng::new(10);
    let mut p10 = b"UR:BYTES/".to_vec();
    for _ in 0..180 {
        p10.push(b'A' + rng.below(26) as u8);
    }
    out.push(Payload {
        number: 10,
        id: "P10 ur-alnum",
        segments: vec![Segment::Alphanumeric(p10.clone())],
        expected: p10,
        ec_levels: vec![EcLevel::L, EcLevel::M],
    });

    let mut rng = Rng::new(11);
    let p11: Vec<u8> = (0..1000).map(|_| rng.next_u8()).collect();
    out.push(Payload {
        number: 11,
        id: "P11 binary-1000",
        segments: vec![Segment::Byte(p11.clone())],
        expected: p11,
        ec_levels: vec![EcLevel::L, EcLevel::M],
    });

    let mut p12 = Vec::new();
    p12.extend_from_slice(b"0123456789");
    p12.extend_from_slice(&[0x00, 0x61, 0x62, 0x63, 0xff]);
    p12.extend_from_slice(b"HELLO WORLD");
    out.push(Payload {
        number: 12,
        id: "P12 mixed",
        segments: vec![
            Segment::Numeric(b"0123456789".to_vec()),
            Segment::Byte(vec![0x00, 0x61, 0x62, 0x63, 0xff]),
            Segment::Alphanumeric(b"HELLO WORLD".to_vec()),
        ],
        expected: p12,
        ec_levels: vec![EcLevel::M],
    });

    let p13 = vec![0xc3, 0xa9, 0x74, 0xc3, 0xa9];
    out.push(Payload {
        number: 13,
        id: "P13 eci-utf8",
        segments: vec![Segment::Eci(26), Segment::Byte(p13.clone())],
        expected: p13,
        ec_levels: vec![EcLevel::M],
    });

    let p14 = vec![0xe9, 0x74, 0xe9];
    out.push(Payload {
        number: 14,
        id: "P14 eci-latin1",
        segments: vec![Segment::Eci(3), Segment::Byte(p14.clone())],
        expected: p14,
        ec_levels: vec![EcLevel::M],
    });

    let p15 = vec![0x93, 0x5f, 0xe4, 0xaa];
    out.push(Payload {
        number: 15,
        id: "P15 kanji",
        segments: vec![Segment::Kanji(p15.clone())],
        expected: p15,
        ec_levels: vec![EcLevel::M],
    });

    out
}

pub fn encode(payload: &Payload, ec: EcLevel) -> QrCode {
    for version in 1i16..=40 {
        let mut bits = Bits::new(Version::Normal(version));
        let mut fits = true;
        for segment in &payload.segments {
            let result = match segment {
                Segment::Numeric(data) => bits.push_numeric_data(data),
                Segment::Alphanumeric(data) => bits.push_alphanumeric_data(data),
                Segment::Byte(data) => bits.push_byte_data(data),
                Segment::Eci(designator) => bits.push_eci_designator(*designator),
                Segment::Kanji(data) => bits.push_kanji_data(data),
            };
            if result.is_err() {
                fits = false;
                break;
            }
        }
        if !fits {
            continue;
        }
        if bits.push_terminator(ec).is_err() {
            continue;
        }
        if let Ok(code) = QrCode::with_bits(bits, ec) {
            return code;
        }
    }
    panic!("payload {} does not fit any version at {ec:?}", payload.id);
}

pub fn ec_name(ec: EcLevel) -> &'static str {
    match ec {
        EcLevel::L => "L",
        EcLevel::M => "M",
        EcLevel::Q => "Q",
        EcLevel::H => "H",
    }
}

pub fn module_colors(code: &QrCode) -> Vec<bool> {
    code.to_colors().into_iter().map(|color| color == Color::Dark).collect()
}

pub fn render_modules(modules: &[bool], width: usize, m: usize, q: usize, dark: u8, light: u8) -> Raster {
    let total = (width + 2 * q) * m;
    let mut out = Raster::new(total, total, light);
    for my in 0..width {
        for mx in 0..width {
            if modules[my * width + mx] {
                for py in 0..m {
                    for px in 0..m {
                        out.set((q + mx) * m + px, (q + my) * m + py, dark);
                    }
                }
            }
        }
    }
    out
}

pub fn render(code: &QrCode, m: usize, q: usize, dark: u8, light: u8) -> Raster {
    render_modules(&module_colors(code), code.width(), m, q, dark, light)
}

pub fn degrade(id: &str, code: &QrCode, seed: &str) -> Raster {
    let mut rng = Rng::from_name(seed);
    match id {
        "D1" => render(code, 4, 4, 0, 255),
        "D2" => render(code, 2, 4, 0, 255),
        "D3" => render(code, 1, 4, 0, 255),
        "D4" => render(code, 8, 4, 0, 255),
        "D5" => render(code, 4, 1, 0, 255),
        "D6" => render(code, 4, 0, 0, 255),
        "D7" => {
            let mut raster = render(code, 4, 4, 0, 255);
            raster.box_blur(1);
            raster
        }
        "D8" => {
            let mut raster = render(code, 4, 4, 0, 255);
            raster.box_blur(2);
            raster
        }
        "D9" => {
            let mut raster = render(code, 6, 4, 0, 255);
            raster.box_blur(3);
            raster
        }
        "D10" => {
            let mut raster = render(code, 4, 4, 0, 255);
            raster.add_noise(&mut rng, 20.0);
            raster
        }
        "D11" => {
            let mut raster = render(code, 4, 4, 0, 255);
            raster.add_noise(&mut rng, 45.0);
            raster
        }
        "D12" => render(code, 4, 4, 100, 160),
        "D13" => {
            let mut raster = render(code, 4, 4, 40, 110);
            raster.add_noise(&mut rng, 10.0);
            raster
        }
        "D14" => {
            let mut raster = render(code, 4, 4, 0, 255);
            raster.add_gradient(80.0);
            let w = raster.w as f64;
            let h = raster.h as f64;
            raster.add_radial_highlight(0.7 * w, 0.3 * h, w / 4.0, 200.0);
            raster
        }
        "D15" => render(code, 4, 4, 0, 255).rotate(10.0),
        "D16" => render(code, 4, 4, 0, 255).rotate(45.0),
        "D17" => render(code, 4, 4, 0, 255).rotate90(),
        "D18" => render(code, 4, 4, 0, 255).rotate180(),
        "D19" => render(code, 4, 4, 0, 255).keystone(0.15),
        "D20" => render(code, 4, 4, 0, 255).keystone(0.35),
        "D21" => render(code, 4, 4, 0, 255).resize(0.6),
        "D22" => {
            let mut raster = render(code, 4, 4, 0, 255);
            raster.invert();
            raster
        }
        "D23" => render(code, 4, 4, 0, 255).mirror(),
        "D24" => {
            let symbol = render(code, 3, 4, 0, 255);
            let mut frame = smooth_texture(1280, 720, &mut rng);
            paste(&mut frame, &symbol, 700, 200);
            frame
        }
        "D25" => occlude(render(code, 4, 4, 0, 255), code.width()),
        "D26" => {
            let raster = render(code, 5, 4, 70, 190);
            let raster = raster.rotate(7.0);
            let mut raster = raster.keystone(0.10);
            raster.box_blur(1);
            raster.add_gradient(40.0);
            raster.add_noise(&mut rng, 12.0);
            raster
        }
        "D27" => {
            let mut raster = render(code, 4, 4, 0, 255);
            raster.blockiness();
            raster
        }
        other => panic!("unknown degradation {other}"),
    }
}

pub fn synthetic_cases() -> Vec<Case> {
    let mut out = Vec::new();
    for payload in payloads() {
        for &ec in &payload.ec_levels {
            let code = encode(&payload, ec);
            for d in 1..=27 {
                let degradation = format!("D{d}");
                let name = format!("{} {} {}", payload.id, ec_name(ec), degradation);
                let raster = degrade(&degradation, &code, &name);
                out.push(Case {
                    name,
                    payload_id: payload.id.to_string(),
                    degradation,
                    ec: ec_name(ec).to_string(),
                    raster,
                    expected: Some(payload.expected.clone()),
                });
            }
        }
    }
    out
}

pub fn two_code_cases() -> Vec<TwoCodeCase> {
    let payloads = payloads();
    let mut out = Vec::new();
    for (a, b, name) in [
        ("P8 words", "P9 wif", "P8 + P9"),
        ("P5 compact32-nul", "P6 compact16-crlf", "P5 + P6"),
    ] {
        let pa = payloads.iter().find(|p| p.id == a).expect("payload");
        let pb = payloads.iter().find(|p| p.id == b).expect("payload");
        let ca = encode(pa, EcLevel::M);
        let cb = encode(pb, EcLevel::M);
        let ra = render(&ca, 4, 4, 0, 255);
        let rb = render(&cb, 4, 4, 0, 255);
        let gap = 40;
        let w = ra.w + gap + rb.w;
        let h = ra.h.max(rb.h);
        let mut frame = Raster::new(w, h, 255);
        paste(&mut frame, &ra, 0, 0);
        paste(&mut frame, &rb, ra.w + gap, 0);
        out.push(TwoCodeCase {
            name: name.to_string(),
            raster: frame,
            expected: vec![pa.expected.clone(), pb.expected.clone()],
        });
    }
    out
}

pub fn flipped_cases() -> Vec<FlipCase> {
    let payloads = payloads();
    let mut out = Vec::new();
    for (id, ec, fraction, seeds) in [
        ("P11 binary-1000", EcLevel::L, 0.05, 50usize),
        ("P8 words", EcLevel::M, 0.05, 50),
        ("P8 words", EcLevel::M, 0.01, 50),
    ] {
        let payload = payloads.iter().find(|p| p.id == id).expect("payload");
        let code = encode(payload, ec);
        let width = code.width();
        let base = module_colors(&code);
        let mut candidates = Vec::new();
        for y in 0..width {
            for x in 0..width {
                if !code.is_functional(x, y) {
                    candidates.push((x, y));
                }
            }
        }
        let group = format!("{id} {} {:.0}%", ec_name(ec), fraction * 100.0);
        for seed in 0..seeds {
            let mut rng = Rng::new(0x5EED_0000 + seed as u64);
            let mut modules = base.clone();
            let mut pool = candidates.clone();
            rng.shuffle(&mut pool);
            let flips = (pool.len() as f64 * fraction).round() as usize;
            for &(x, y) in &pool[..flips] {
                modules[y * width + x] = !modules[y * width + x];
            }
            let raster = render_modules(&modules, width, 4, 4, 0, 255);
            out.push(FlipCase {
                group: group.clone(),
                name: format!("{group} seed {seed}"),
                raster,
                expected: payload.expected.clone(),
            });
        }
    }
    out
}

pub fn robustness_cases() -> Vec<RobustCase> {
    let mut out = Vec::new();
    out.push(RobustCase { name: "uniform white 640x480".into(), raster: Raster::new(640, 480, 255) });
    out.push(RobustCase { name: "uniform black 640x480".into(), raster: Raster::new(640, 480, 0) });
    out.push(RobustCase { name: "degenerate 1x1".into(), raster: Raster::new(1, 1, 128) });
    out.push(RobustCase { name: "degenerate 2x2".into(), raster: Raster::new(2, 2, 128) });
    out.push(RobustCase { name: "degenerate 4000x1".into(), raster: Raster::new(4000, 1, 128) });
    out.push(RobustCase { name: "degenerate 1x4000".into(), raster: Raster::new(1, 4000, 128) });

    let mut rng = Rng::from_name("robust-noise");
    let mut noise = Raster::new(640, 480, 0);
    for value in noise.gray.iter_mut() {
        *value = rng.next_u8();
    }
    out.push(RobustCase { name: "uniform noise 640x480".into(), raster: noise });

    out.push(RobustCase { name: "checkerboard 1px".into(), raster: checkerboard(640, 480, 1) });
    out.push(RobustCase { name: "checkerboard 8px".into(), raster: checkerboard(640, 480, 8) });
    out.push(RobustCase { name: "64 fake finders".into(), raster: fake_finders() });

    for seed in 0..50 {
        out.push(RobustCase { name: format!("random grid {seed}"), raster: random_grid(seed) });
    }

    out.push(RobustCase { name: "large blank 4096x4096".into(), raster: Raster::new(4096, 4096, 255) });

    let payloads = payloads();
    let p8 = payloads.iter().find(|p| p.id == "P8 words").expect("payload");
    let code = encode(p8, EcLevel::M);
    let mut striped = render(&code, 4, 4, 0, 255);
    for y in (0..striped.h).step_by(2) {
        for x in 0..striped.w {
            striped.set(x, y, 255 - striped.get(x, y));
        }
    }
    out.push(RobustCase { name: "striped P8".into(), raster: striped });

    out
}

fn hex(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = (pair[0] as char).to_digit(16).expect("hex") as u8;
        let lo = (pair[1] as char).to_digit(16).expect("hex") as u8;
        out.push(hi << 4 | lo);
    }
    out
}

fn smooth_texture(w: usize, h: usize, rng: &mut Rng) -> Raster {
    let cells_x = 32;
    let cells_y = 18;
    let mut coarse = vec![0.0f64; (cells_x + 1) * (cells_y + 1)];
    for value in coarse.iter_mut() {
        *value = 150.0 + rng.next_f64() * 80.0;
    }
    let mut out = Raster::new(w, h, 0);
    for y in 0..h {
        for x in 0..w {
            let fx = x as f64 / (w.max(2) - 1) as f64 * cells_x as f64;
            let fy = y as f64 / (h.max(2) - 1) as f64 * cells_y as f64;
            let x0 = fx.floor() as usize;
            let y0 = fy.floor() as usize;
            let tx = fx - x0 as f64;
            let ty = fy - y0 as f64;
            let x1 = (x0 + 1).min(cells_x);
            let y1 = (y0 + 1).min(cells_y);
            let value = coarse[y0 * (cells_x + 1) + x0] * (1.0 - tx) * (1.0 - ty)
                + coarse[y0 * (cells_x + 1) + x1] * tx * (1.0 - ty)
                + coarse[y1 * (cells_x + 1) + x0] * (1.0 - tx) * ty
                + coarse[y1 * (cells_x + 1) + x1] * tx * ty;
            out.set(x, y, value.round().clamp(0.0, 255.0) as u8);
        }
    }
    out
}

fn paste(dst: &mut Raster, src: &Raster, ox: usize, oy: usize) {
    for y in 0..src.h {
        for x in 0..src.w {
            let dx = ox + x;
            let dy = oy + y;
            if dx < dst.w && dy < dst.h {
                dst.set(dx, dy, src.get(x, y));
            }
        }
    }
}

fn occlude(mut raster: Raster, width: usize) -> Raster {
    let m = 4;
    let q = 4;
    let symbol = width * m;
    let side = ((0.12_f64).sqrt() * symbol as f64).round() as usize;
    let centre_x = q * m + (symbol as f64 * 0.75) as usize;
    let centre_y = q * m + (symbol as f64 * 0.75) as usize;
    let x0 = centre_x.saturating_sub(side / 2);
    let y0 = centre_y.saturating_sub(side / 2);
    for y in y0..(y0 + side).min(raster.h) {
        for x in x0..(x0 + side).min(raster.w) {
            raster.set(x, y, 128);
        }
    }
    raster
}

fn checkerboard(w: usize, h: usize, cell: usize) -> Raster {
    let mut out = Raster::new(w, h, 0);
    for y in 0..h {
        for x in 0..w {
            let dark = ((x / cell) + (y / cell)) % 2 == 0;
            out.set(x, y, if dark { 0 } else { 255 });
        }
    }
    out
}

fn fake_finders() -> Raster {
    let mut rng = Rng::from_name("robust-fake-finders");
    let mut out = Raster::new(1024, 1024, 255);
    let m = 3;
    let size = 7 * m;
    for _ in 0..64 {
        let x = rng.below(1024 - size);
        let y = rng.below(1024 - size);
        draw_finder(&mut out, x, y, m);
    }
    out
}

fn draw_finder(out: &mut Raster, x0: usize, y0: usize, m: usize) {
    for my in 0..7 {
        for mx in 0..7 {
            let dark = match my {
                0 | 6 => true,
                1 | 5 => mx == 0 || mx == 6,
                _ => mx == 0 || mx == 6 || (2..=4).contains(&mx),
            };
            if dark {
                for py in 0..m {
                    for px in 0..m {
                        out.set(x0 + mx * m + px, y0 + my * m + py, 0);
                    }
                }
            }
        }
    }
}

fn random_grid(seed: usize) -> Raster {
    let mut rng = Rng::new(0xABCD_0000 + seed as u64);
    let width = 25;
    let mut modules = vec![false; width * width];
    for &(ox, oy) in &[(0usize, 0usize), (18, 0), (0, 18)] {
        for my in 0..7 {
            for mx in 0..7 {
                let dark = match my {
                    0 | 6 => true,
                    1 | 5 => mx == 0 || mx == 6,
                    _ => mx == 0 || mx == 6 || (2..=4).contains(&mx),
                };
                modules[(oy + my) * width + ox + mx] = dark;
            }
        }
    }
    for i in 8..17 {
        modules[6 * width + i] = i % 2 == 0;
        modules[i * width + 6] = i % 2 == 0;
    }
    for y in 0..width {
        for x in 0..width {
            let in_finder = (x < 8 && y < 8) || (x >= 17 && y < 8) || (x < 8 && y >= 17);
            let in_timing = x == 6 || y == 6;
            if !in_finder && !in_timing {
                modules[y * width + x] = rng.next_u64() & 1 == 1;
            }
        }
    }
    render_modules(&modules, width, 4, 4, 0, 255)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decoders::{classify, run_quircs, run_rqrr, with_silent_panics, Outcome};

    #[test]
    fn render_size_and_quiet_zone() {
        let payload = payloads().into_iter().find(|p| p.number == 8).expect("P8");
        let code = encode(&payload, EcLevel::M);
        let raster = degrade("D1", &code, "render-test");
        let expected = (code.width() + 2 * 4) * 4;
        assert_eq!(raster.w, expected);
        assert_eq!(raster.h, expected);
        let quiet = 4 * 4;
        for y in 0..raster.h {
            for x in 0..raster.w {
                if x < quiet || y < quiet || x >= raster.w - quiet || y >= raster.h - quiet {
                    assert_eq!(raster.get(x, y), 255, "quiet zone at ({x}, {y})");
                }
            }
        }
    }

    #[test]
    fn corpus_sanity() {
        let payloads = payloads();
        let mut failures = Vec::new();
        for payload in payloads.iter().filter(|p| p.number <= 11) {
            let code = encode(payload, EcLevel::M);
            let raster = degrade("D1", &code, &format!("sanity-{}", payload.id));
            let rqrr = with_silent_panics(|| run_rqrr(&raster.gray, raster.w, raster.h));
            let quircs = with_silent_panics(|| run_quircs(&raster.gray, raster.w, raster.h));
            let a = classify(&rqrr, Some(&payload.expected));
            let b = classify(&quircs, Some(&payload.expected));
            if a != Outcome::Exact && b != Outcome::Exact {
                failures.push(format!("{}: rqrr {a:?}, quircs {b:?}", payload.id));
            }
        }
        assert!(failures.is_empty(), "{}", failures.join("\n"));
    }
}
