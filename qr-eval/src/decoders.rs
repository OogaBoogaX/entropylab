//! Adapters for the two candidate decoders, with panic containment and timing.

use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Instant;

#[derive(Clone, Debug, Default)]
pub struct Info {
    pub data_type: Option<String>,
    pub eci: Option<String>,
}

#[derive(Clone, Debug)]
pub enum CodeOutcome {
    Decoded { bytes: Vec<u8>, info: Info },
    Error(String),
}

#[derive(Clone, Debug)]
pub enum RunResult {
    Codes(Vec<CodeOutcome>),
    Panic(String),
}

#[derive(Clone, Debug)]
pub struct Run {
    pub result: RunResult,
    pub ms: f64,
}

impl Run {
    pub fn codes(&self) -> &[CodeOutcome] {
        match &self.result {
            RunResult::Codes(codes) => codes,
            RunResult::Panic(_) => &[],
        }
    }

    pub fn decoded(&self) -> Vec<&[u8]> {
        self.codes()
            .iter()
            .filter_map(|code| match code {
                CodeOutcome::Decoded { bytes, .. } => Some(bytes.as_slice()),
                CodeOutcome::Error(_) => None,
            })
            .collect()
    }

    pub fn panic_text(&self) -> Option<&str> {
        match &self.result {
            RunResult::Panic(text) => Some(text),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Exact,
    Wrong,
    NotFound,
    Error,
    Panic,
    FalsePositive,
}

impl Outcome {
    pub fn index(self) -> usize {
        match self {
            Outcome::Exact => 0,
            Outcome::Wrong => 1,
            Outcome::NotFound => 2,
            Outcome::Error => 3,
            Outcome::Panic => 4,
            Outcome::FalsePositive => 5,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Outcome::Exact => "Exact",
            Outcome::Wrong => "Wrong",
            Outcome::NotFound => "NotFound",
            Outcome::Error => "Error",
            Outcome::Panic => "Panic",
            Outcome::FalsePositive => "FalsePositive",
        }
    }
}

pub fn classify(run: &Run, expected: Option<&[u8]>) -> Outcome {
    if run.panic_text().is_some() {
        return Outcome::Panic;
    }
    if run.codes().is_empty() {
        return Outcome::NotFound;
    }
    let decoded = run.decoded();
    match expected {
        Some(expected) => {
            // Exact only when every decoded code is the expected payload: the
            // right code next to a wrong one is a wrong-bytes result.
            if decoded.is_empty() {
                Outcome::Error
            } else if decoded.iter().all(|bytes| *bytes == expected) {
                Outcome::Exact
            } else {
                Outcome::Wrong
            }
        }
        None => {
            if decoded.is_empty() {
                Outcome::Error
            } else {
                Outcome::FalsePositive
            }
        }
    }
}

fn panic_text(payload: Box<dyn std::any::Any + Send>) -> String {
    if let Some(text) = payload.downcast_ref::<&str>() {
        (*text).to_string()
    } else if let Some(text) = payload.downcast_ref::<String>() {
        text.clone()
    } else {
        "panic".to_string()
    }
}

/// Run `f` with a silent panic hook, restoring the previous hook afterwards.
pub fn with_silent_panics<T>(f: impl FnOnce() -> T) -> T {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(|_| {}));
    let out = f();
    std::panic::set_hook(previous);
    out
}

pub fn run_rqrr(gray: &[u8], w: usize, h: usize) -> Run {
    let start = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut image = rqrr::PreparedImage::prepare_from_greyscale(w, h, |x, y| gray[y * w + x]);
        let grids = image.detect_grids();
        let mut out = Vec::with_capacity(grids.len());
        for grid in grids {
            let mut bytes = Vec::new();
            match grid.decode_to(&mut bytes) {
                Ok(_meta) => out.push(CodeOutcome::Decoded { bytes, info: Info::default() }),
                Err(error) => out.push(CodeOutcome::Error(format!("{error:?}"))),
            }
        }
        out
    }));
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    match result {
        Ok(codes) => Run { result: RunResult::Codes(codes), ms },
        Err(payload) => Run { result: RunResult::Panic(panic_text(payload)), ms },
    }
}

pub fn run_quircs(gray: &[u8], w: usize, h: usize) -> Run {
    let start = Instant::now();
    let result = catch_unwind(AssertUnwindSafe(|| {
        let mut quirc = quircs::Quirc::default();
        let mut out = Vec::new();
        for code in quirc.identify(w, h, gray) {
            match code {
                Ok(code) => match code.decode() {
                    Ok(data) => {
                        let quircs::Data { payload, data_type, eci, .. } = data;
                        out.push(CodeOutcome::Decoded {
                            bytes: payload,
                            info: Info {
                                data_type: data_type.map(|kind| kind.to_string()),
                                eci: eci.map(|value| format!("{value:?}")),
                            },
                        });
                    }
                    Err(error) => out.push(CodeOutcome::Error(format!("{error}"))),
                },
                Err(error) => out.push(CodeOutcome::Error(format!("{error}"))),
            }
        }
        out
    }));
    let ms = start.elapsed().as_secs_f64() * 1000.0;
    match result {
        Ok(codes) => Run { result: RunResult::Codes(codes), ms },
        Err(payload) => Run { result: RunResult::Panic(panic_text(payload)), ms },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decoded(bytes: &[u8]) -> Run {
        Run {
            result: RunResult::Codes(vec![CodeOutcome::Decoded {
                bytes: bytes.to_vec(),
                info: Info::default(),
            }]),
            ms: 0.0,
        }
    }

    fn errored() -> Run {
        Run {
            result: RunResult::Codes(vec![CodeOutcome::Error("x".to_string())]),
            ms: 0.0,
        }
    }

    fn empty() -> Run {
        Run { result: RunResult::Codes(Vec::new()), ms: 0.0 }
    }

    fn panicked() -> Run {
        Run { result: RunResult::Panic("boom".to_string()), ms: 0.0 }
    }

    #[test]
    fn classification_maps_every_outcome() {
        assert_eq!(classify(&decoded(b"abc"), Some(b"abc")), Outcome::Exact);
        assert_eq!(classify(&decoded(b"abd"), Some(b"abc")), Outcome::Wrong);
        assert_eq!(classify(&empty(), Some(b"abc")), Outcome::NotFound);
        assert_eq!(classify(&errored(), Some(b"abc")), Outcome::Error);
        assert_eq!(classify(&panicked(), Some(b"abc")), Outcome::Panic);
        assert_eq!(classify(&decoded(b"abc"), None), Outcome::FalsePositive);
        assert_eq!(classify(&errored(), None), Outcome::Error);
        assert_eq!(classify(&empty(), None), Outcome::NotFound);
        let right = || CodeOutcome::Decoded { bytes: b"abc".to_vec(), info: Info::default() };
        let wrong = || CodeOutcome::Decoded { bytes: b"evil".to_vec(), info: Info::default() };
        let codes = |outcomes| Run { result: RunResult::Codes(outcomes), ms: 0.0 };
        assert_eq!(classify(&codes(vec![right(), wrong()]), Some(b"abc")), Outcome::Wrong, "a wrong code beside the right one is Wrong");
        assert_eq!(classify(&codes(vec![wrong(), right()]), Some(b"abc")), Outcome::Wrong);
        assert_eq!(classify(&codes(vec![right(), CodeOutcome::Error("x".to_string())]), Some(b"abc")), Outcome::Exact);
        assert_eq!(classify(&codes(vec![right(), right()]), Some(b"abc")), Outcome::Exact);
    }
}
