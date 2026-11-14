//! Independent fixtures: SeedSigner's published SeedQR images and photos.

use std::io::BufReader;
use std::path::{Path, PathBuf};

use crate::raster::Raster;

pub struct Fixture {
    pub file: String,
    pub image: String,
    pub format: String,
    pub expected_hex: String,
    pub expected: Option<Vec<u8>>,
    pub note: String,
}

pub fn fixtures_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

pub fn load_manifest() -> Result<Vec<Fixture>, String> {
    let path = fixtures_dir().join("manifest.tsv");
    let text = std::fs::read_to_string(&path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut out = Vec::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim_end_matches('\r');
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let columns: Vec<&str> = line.split('\t').collect();
        if columns.len() < 5 {
            return Err(format!("manifest line {}: expected 5 tab-separated columns", index + 1));
        }
        let expected = if columns[3] == "-" {
            None
        } else {
            Some(hex_decode(columns[3]).map_err(|e| format!("manifest line {}: {e}", index + 1))?)
        };
        out.push(Fixture {
            file: columns[0].to_string(),
            image: columns[1].to_string(),
            format: columns[2].to_string(),
            expected_hex: columns[3].to_string(),
            expected,
            note: columns[4].to_string(),
        });
    }
    Ok(out)
}

pub fn load_image(fixture: &Fixture) -> Result<Raster, String> {
    let path = fixtures_dir().join(&fixture.file);
    match fixture.image.as_str() {
        "png" => load_png(&path),
        "jpeg" => load_jpeg(&path),
        other => Err(format!("{}: unknown image type {other}", fixture.file)),
    }
}

fn load_png(path: &Path) -> Result<Raster, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut decoder = png::Decoder::new(BufReader::new(file));
    decoder.set_transformations(png::Transformations::EXPAND | png::Transformations::STRIP_16);
    let mut reader = decoder.read_info().map_err(|e| format!("{}: {e}", path.display()))?;
    let size = reader
        .output_buffer_size()
        .ok_or_else(|| format!("{}: image too large", path.display()))?;
    let mut buffer = vec![0u8; size];
    let info = reader
        .next_frame(&mut buffer)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    let data = &buffer[..info.buffer_size()];
    let (w, h) = (info.width as usize, info.height as usize);
    let mut gray = vec![0u8; w * h];
    match info.color_type {
        png::ColorType::Grayscale => {
            gray.copy_from_slice(&data[..w * h]);
        }
        png::ColorType::GrayscaleAlpha => {
            for i in 0..w * h {
                let value = data[i * 2] as u32;
                let alpha = data[i * 2 + 1] as u32;
                gray[i] = ((value * alpha + 255 * (255 - alpha)) / 255) as u8;
            }
        }
        png::ColorType::Rgb => {
            for i in 0..w * h {
                gray[i] = luminance(data[i * 3], data[i * 3 + 1], data[i * 3 + 2]);
            }
        }
        png::ColorType::Rgba => {
            for i in 0..w * h {
                let r = data[i * 4] as u32;
                let g = data[i * 4 + 1] as u32;
                let b = data[i * 4 + 2] as u32;
                let alpha = data[i * 4 + 3] as u32;
                let luma = luminance_u32(r, g, b);
                gray[i] = ((luma * alpha + 255 * (255 - alpha)) / 255) as u8;
            }
        }
        _ => return Err(format!("{}: unsupported colour type", path.display())),
    }
    Ok(Raster::from_vec(w, h, gray))
}

fn load_jpeg(path: &Path) -> Result<Raster, String> {
    let file = std::fs::File::open(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut decoder = jpeg_decoder::Decoder::new(BufReader::new(file));
    let pixels = decoder.decode().map_err(|e| format!("{}: {e}", path.display()))?;
    let info = decoder
        .info()
        .ok_or_else(|| format!("{}: no image info", path.display()))?;
    let (w, h) = (info.width as usize, info.height as usize);
    let mut gray = vec![0u8; w * h];
    match info.pixel_format {
        jpeg_decoder::PixelFormat::L8 => {
            gray.copy_from_slice(&pixels[..w * h]);
        }
        jpeg_decoder::PixelFormat::L16 => {
            for i in 0..w * h {
                gray[i] = pixels[i * 2];
            }
        }
        jpeg_decoder::PixelFormat::RGB24 => {
            for i in 0..w * h {
                gray[i] = luminance(pixels[i * 3], pixels[i * 3 + 1], pixels[i * 3 + 2]);
            }
        }
        jpeg_decoder::PixelFormat::CMYK32 => {
            for i in 0..w * h {
                let c = pixels[i * 4] as u32;
                let m = pixels[i * 4 + 1] as u32;
                let y = pixels[i * 4 + 2] as u32;
                let k = pixels[i * 4 + 3] as u32;
                let ink = c.max(m).max(y);
                let value = 255u32.saturating_sub(ink);
                gray[i] = ((value * (255 - k)) / 255) as u8;
            }
        }
    }
    Ok(Raster::from_vec(w, h, gray))
}

pub fn luminance(r: u8, g: u8, b: u8) -> u8 {
    luminance_u32(r as u32, g as u32, b as u32) as u8
}

fn luminance_u32(r: u32, g: u32, b: u32) -> u32 {
    (299 * r + 587 * g + 114 * b + 500) / 1000
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    let bytes = s.as_bytes();
    if bytes.len() % 2 != 0 {
        return Err("odd number of hex digits".to_string());
    }
    let mut out = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks(2) {
        let hi = hex_digit(pair[0])?;
        let lo = hex_digit(pair[1])?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

fn hex_digit(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(format!("invalid hex digit {:?}", byte as char)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn luminance_vectors() {
        assert_eq!(luminance(255, 255, 255), 255);
        assert_eq!(luminance(0, 0, 0), 0);
        assert_eq!(luminance(255, 0, 0), 76);
    }

    #[test]
    fn manifest_rows_are_well_formed() {
        let fixtures = load_manifest().expect("manifest");
        assert!(!fixtures.is_empty(), "manifest is empty");
        for fixture in &fixtures {
            let path = fixtures_dir().join(&fixture.file);
            assert!(path.is_file(), "missing fixture {}", fixture.file);
            assert!(
                fixture.image == "png" || fixture.image == "jpeg",
                "{}: image must be png or jpeg, got {}",
                fixture.file,
                fixture.image
            );
            if fixture.expected_hex != "-" {
                assert!(
                    fixture
                        .expected_hex
                        .chars()
                        .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)),
                    "{}: expected_hex is not lowercase hex",
                    fixture.file
                );
                let bytes = fixture.expected_hex.len() / 2;
                assert!(
                    [16, 32, 48, 96].contains(&bytes),
                    "{}: expected_hex is {bytes} bytes",
                    fixture.file
                );
                // A Standard SeedQR payload is 12 or 24 four-digit BIP39 word
                // indexes in ASCII; checked here independently of any decoder.
                if fixture.format == "standard-seedqr" {
                    let raw: Vec<u8> = (0..bytes)
                        .map(|i| u8::from_str_radix(&fixture.expected_hex[2 * i..2 * i + 2], 16).unwrap())
                        .collect();
                    assert!([48, 96].contains(&raw.len()), "{}: not 12 or 24 indexes", fixture.file);
                    assert!(raw.iter().all(u8::is_ascii_digit), "{}: not ASCII digits", fixture.file);
                    for index in raw.chunks(4) {
                        let n: u32 = std::str::from_utf8(index).unwrap().parse().unwrap();
                        assert!(n < 2048, "{}: word index {n} out of range", fixture.file);
                    }
                }
            }
        }
    }
}
