//! QR decoder evaluation harness: rqrr vs quircs on synthetic and real images.
//!
//! `cargo run --release` prints a Markdown report to stdout. Nothing here is
//! built into EntropyLab; it exists only to choose a decoder for the camera
//! "Scan QR" import.

mod corpus;
mod decoders;
mod fixtures;
mod prng;
mod raster;
mod report;

use std::process::ExitCode;

fn main() -> ExitCode {
    // Decoder panics are data, not noise: record them without printing.
    std::panic::set_hook(Box::new(|_| {}));

    let manifest = match fixtures::load_manifest() {
        Ok(manifest) => manifest,
        Err(error) => {
            eprintln!("qr-eval: {error}");
            return ExitCode::FAILURE;
        }
    };

    let synthetic_cases = corpus::synthetic_cases();
    let mut synthetic = Vec::with_capacity(synthetic_cases.len());
    for case in &synthetic_cases {
        let rqrr = decoders::run_rqrr(&case.raster.gray, case.raster.w, case.raster.h);
        let quircs = decoders::run_quircs(&case.raster.gray, case.raster.w, case.raster.h);
        synthetic.push(report::CaseResult {
            name: case.name.clone(),
            payload_id: case.payload_id.clone(),
            degradation: case.degradation.clone(),
            ec: case.ec.clone(),
            expected: case.expected.clone(),
            rqrr,
            quircs,
        });
    }

    let mut fixture_results = Vec::new();
    for fixture in manifest {
        let raster = match fixtures::load_image(&fixture) {
            Ok(raster) => raster,
            Err(error) => {
                eprintln!("qr-eval: {error}");
                return ExitCode::FAILURE;
            }
        };
        let as_is = (
            decoders::run_rqrr(&raster.gray, raster.w, raster.h),
            decoders::run_quircs(&raster.gray, raster.w, raster.h),
        );
        let mut blurred = raster.clone();
        blurred.box_blur(1);
        let blur = (
            decoders::run_rqrr(&blurred.gray, blurred.w, blurred.h),
            decoders::run_quircs(&blurred.gray, blurred.w, blurred.h),
        );
        let rotated = raster.rotate(10.0);
        let rotate = (
            decoders::run_rqrr(&rotated.gray, rotated.w, rotated.h),
            decoders::run_quircs(&rotated.gray, rotated.w, rotated.h),
        );
        fixture_results.push(report::FixtureResult { fixture, as_is, blur, rotate });
    }

    let mut two_code = Vec::new();
    for case in corpus::two_code_cases() {
        let rqrr = decoders::run_rqrr(&case.raster.gray, case.raster.w, case.raster.h);
        let quircs = decoders::run_quircs(&case.raster.gray, case.raster.w, case.raster.h);
        two_code.push(report::TwoCodeResult {
            name: case.name,
            expected: case.expected,
            rqrr,
            quircs,
        });
    }

    let mut flipped = Vec::new();
    for case in corpus::flipped_cases() {
        let rqrr = decoders::run_rqrr(&case.raster.gray, case.raster.w, case.raster.h);
        let quircs = decoders::run_quircs(&case.raster.gray, case.raster.w, case.raster.h);
        flipped.push(report::FlipResult {
            group: case.group,
            name: case.name,
            expected: case.expected,
            rqrr,
            quircs,
        });
    }

    let mut robust = Vec::new();
    for case in corpus::robustness_cases() {
        let rqrr = decoders::run_rqrr(&case.raster.gray, case.raster.w, case.raster.h);
        let quircs = decoders::run_quircs(&case.raster.gray, case.raster.w, case.raster.h);
        robust.push(report::RobustResult { name: case.name, rqrr, quircs });
    }

    print!(
        "{}",
        report::render(&synthetic, &fixture_results, &two_code, &flipped, &robust)
    );
    ExitCode::SUCCESS
}
