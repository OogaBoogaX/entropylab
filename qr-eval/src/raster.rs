//! Greyscale raster and the image operations the corpus needs.

use crate::prng::Rng;

#[derive(Clone)]
pub struct Raster {
    pub w: usize,
    pub h: usize,
    pub gray: Vec<u8>,
}

impl Raster {
    pub fn new(w: usize, h: usize, fill: u8) -> Self {
        Self { w, h, gray: vec![fill; w * h] }
    }

    pub fn from_vec(w: usize, h: usize, gray: Vec<u8>) -> Self {
        assert_eq!(gray.len(), w * h, "raster size mismatch");
        Self { w, h, gray }
    }

    pub fn get(&self, x: usize, y: usize) -> u8 {
        self.gray[y * self.w + x]
    }

    pub fn set(&mut self, x: usize, y: usize, value: u8) {
        self.gray[y * self.w + x] = value;
    }

    /// Bilinear sample at continuous coordinates where integers are pixel centres.
    pub fn sample_bilinear(&self, x: f64, y: f64, background: u8) -> u8 {
        if self.w == 0 || self.h == 0 {
            return background;
        }
        let x0 = x.floor();
        let y0 = y.floor();
        let fx = x - x0;
        let fy = y - y0;
        let x0 = x0 as i64;
        let y0 = y0 as i64;
        let at = |xi: i64, yi: i64| -> f64 {
            if xi < 0 || yi < 0 || xi >= self.w as i64 || yi >= self.h as i64 {
                background as f64
            } else {
                self.gray[yi as usize * self.w + xi as usize] as f64
            }
        };
        let value = at(x0, y0) * (1.0 - fx) * (1.0 - fy)
            + at(x0 + 1, y0) * fx * (1.0 - fy)
            + at(x0, y0 + 1) * (1.0 - fx) * fy
            + at(x0 + 1, y0 + 1) * fx * fy;
        value.round().clamp(0.0, 255.0) as u8
    }

    pub fn box_blur(&mut self, radius: usize) {
        if radius == 0 || self.w == 0 || self.h == 0 {
            return;
        }
        let mut horizontal = vec![0u8; self.w * self.h];
        for y in 0..self.h {
            let row = &self.gray[y * self.w..(y + 1) * self.w];
            let out = &mut horizontal[y * self.w..(y + 1) * self.w];
            blur_line(row, out, radius);
        }
        let mut column = vec![0u8; self.h];
        let mut blurred = vec![0u8; self.h];
        for x in 0..self.w {
            for y in 0..self.h {
                column[y] = horizontal[y * self.w + x];
            }
            blur_line(&column, &mut blurred, radius);
            for y in 0..self.h {
                self.gray[y * self.w + x] = blurred[y];
            }
        }
    }

    pub fn rotate(&self, degrees: f64) -> Raster {
        let theta = degrees.to_radians();
        let (sin, cos) = theta.sin_cos();
        let w = self.w as f64;
        let h = self.h as f64;
        let nw = (w * cos.abs() + h * sin.abs()).ceil().max(1.0) as usize;
        let nh = (w * sin.abs() + h * cos.abs()).ceil().max(1.0) as usize;
        let mut out = Raster::new(nw, nh, 255);
        let cx = w / 2.0;
        let cy = h / 2.0;
        let ncx = nw as f64 / 2.0;
        let ncy = nh as f64 / 2.0;
        for y in 0..nh {
            for x in 0..nw {
                let dx = x as f64 + 0.5 - ncx;
                let dy = y as f64 + 0.5 - ncy;
                let sx = dx * cos + dy * sin + cx - 0.5;
                let sy = -dx * sin + dy * cos + cy - 0.5;
                out.set(x, y, self.sample_bilinear(sx, sy, 255));
            }
        }
        out
    }

    pub fn rotate90(&self) -> Raster {
        let mut out = Raster::new(self.h, self.w, 255);
        for dy in 0..out.h {
            for dx in 0..out.w {
                out.set(dx, dy, self.get(dy, self.h - 1 - dx));
            }
        }
        out
    }

    pub fn rotate180(&self) -> Raster {
        let mut out = Raster::new(self.w, self.h, 255);
        for y in 0..self.h {
            for x in 0..self.w {
                out.set(x, y, self.get(self.w - 1 - x, self.h - 1 - y));
            }
        }
        out
    }

    pub fn mirror(&self) -> Raster {
        let mut out = Raster::new(self.w, self.h, 255);
        for y in 0..self.h {
            for x in 0..self.w {
                out.set(x, y, self.get(self.w - 1 - x, y));
            }
        }
        out
    }

    pub fn invert(&mut self) {
        for value in self.gray.iter_mut() {
            *value = 255 - *value;
        }
    }

    pub fn keystone(&self, k: f64) -> Raster {
        let mut out = Raster::new(self.w, self.h, 255);
        if self.w == 0 || self.h == 0 {
            return out;
        }
        let w = self.w as f64;
        for y in 0..self.h {
            let t = if self.h > 1 { y as f64 / (self.h - 1) as f64 } else { 1.0 };
            let scale = 1.0 - k * (1.0 - t);
            let half = (w / 2.0) * scale;
            let left = w / 2.0 - half;
            for x in 0..self.w {
                let u = (x as f64 - left) / (2.0 * half) * w;
                out.set(x, y, self.sample_bilinear(u, y as f64, 255));
            }
        }
        out
    }

    pub fn resize(&self, scale: f64) -> Raster {
        let nw = ((self.w as f64 * scale).round() as usize).max(1);
        let nh = ((self.h as f64 * scale).round() as usize).max(1);
        let mut out = Raster::new(nw, nh, 255);
        for y in 0..nh {
            for x in 0..nw {
                let sx = (x as f64 + 0.5) / scale - 0.5;
                let sy = (y as f64 + 0.5) / scale - 0.5;
                out.set(x, y, self.sample_bilinear(sx, sy, 255));
            }
        }
        out
    }

    pub fn add_gradient(&mut self, amount: f64) {
        if self.w <= 1 {
            return;
        }
        for y in 0..self.h {
            for x in 0..self.w {
                let t = x as f64 / (self.w - 1) as f64;
                let value = self.get(x, y) as f64 + amount * t;
                self.set(x, y, value.round().clamp(0.0, 255.0) as u8);
            }
        }
    }

    pub fn add_radial_highlight(&mut self, cx: f64, cy: f64, radius: f64, amount: f64) {
        if radius <= 0.0 {
            return;
        }
        for y in 0..self.h {
            for x in 0..self.w {
                let dx = x as f64 - cx;
                let dy = y as f64 - cy;
                let distance = (dx * dx + dy * dy).sqrt();
                if distance < radius {
                    let t = 1.0 - distance / radius;
                    let value = self.get(x, y) as f64 + amount * t;
                    self.set(x, y, value.round().clamp(0.0, 255.0) as u8);
                }
            }
        }
    }

    pub fn add_noise(&mut self, rng: &mut Rng, sigma: f64) {
        // Sum of four uniforms has standard deviation 1/sqrt(3); scale to sigma.
        let scale = sigma * 3.0_f64.sqrt();
        for value in self.gray.iter_mut() {
            let sum: f64 = (0..4).map(|_| rng.next_f64()).sum();
            let noise = (sum - 2.0) * scale;
            *value = (*value as f64 + noise).round().clamp(0.0, 255.0) as u8;
        }
    }

    pub fn blockiness(&mut self) {
        for by in (0..self.h).step_by(8) {
            for bx in (0..self.w).step_by(8) {
                let bh = (by + 8).min(self.h);
                let bw = (bx + 8).min(self.w);
                let mut sum = 0u64;
                let mut count = 0u64;
                for y in by..bh {
                    for x in bx..bw {
                        sum += self.get(x, y) as u64;
                        count += 1;
                    }
                }
                let mean = sum as f64 / count as f64;
                for y in by..bh {
                    for x in bx..bw {
                        let value = mean + 0.5 * (self.get(x, y) as f64 - mean);
                        let quantised = (value / 16.0).round() * 16.0;
                        self.set(x, y, quantised.clamp(0.0, 255.0) as u8);
                    }
                }
            }
        }
    }
}

fn blur_line(src: &[u8], dst: &mut [u8], radius: usize) {
    let n = src.len();
    if n == 0 {
        return;
    }
    let mut prefix = vec![0u64; n + 1];
    for i in 0..n {
        prefix[i + 1] = prefix[i] + src[i] as u64;
    }
    for x in 0..n {
        let lo = x.saturating_sub(radius);
        let hi = (x + radius + 1).min(n);
        let count = (hi - lo) as u64;
        dst[x] = ((prefix[hi] - prefix[lo]) / count) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ramp(w: usize, h: usize) -> Raster {
        let mut img = Raster::new(w, h, 0);
        for y in 0..h {
            for x in 0..w {
                img.set(x, y, ((y * w + x) % 256) as u8);
            }
        }
        img
    }

    #[test]
    fn rotate90_is_transpose_then_flip() {
        let img = ramp(3, 2);
        let rotated = img.rotate90();
        let mut transposed = Raster::new(2, 3, 0);
        for y in 0..2 {
            for x in 0..3 {
                transposed.set(y, x, img.get(x, y));
            }
        }
        let mut flipped = Raster::new(2, 3, 0);
        for y in 0..3 {
            for x in 0..2 {
                flipped.set(x, y, transposed.get(1 - x, y));
            }
        }
        assert_eq!(rotated.w, flipped.w);
        assert_eq!(rotated.h, flipped.h);
        assert_eq!(rotated.gray, flipped.gray);
    }

    #[test]
    fn rotate180_twice_is_identity() {
        let img = ramp(5, 3);
        let twice = img.rotate180().rotate180();
        assert_eq!(twice.gray, img.gray);
    }

    #[test]
    fn blur_leaves_uniform_unchanged() {
        let mut img = Raster::new(17, 13, 77);
        img.box_blur(1);
        assert!(img.gray.iter().all(|&v| v == 77));
        img.box_blur(3);
        assert!(img.gray.iter().all(|&v| v == 77));
    }
}
