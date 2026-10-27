//! Markdown report over the collected runs.

use crate::decoders::{classify, CodeOutcome, Outcome, Run};
use crate::fixtures::Fixture;

pub struct CaseResult {
    pub name: String,
    pub payload_id: String,
    pub degradation: String,
    pub ec: String,
    pub expected: Option<Vec<u8>>,
    pub rqrr: Run,
    pub quircs: Run,
}

pub struct FixtureResult {
    pub fixture: Fixture,
    pub as_is: (Run, Run),
    pub blur: (Run, Run),
    pub rotate: (Run, Run),
}

pub struct TwoCodeResult {
    pub name: String,
    pub expected: Vec<Vec<u8>>,
    pub rqrr: Run,
    pub quircs: Run,
}

pub struct FlipResult {
    pub group: String,
    pub name: String,
    pub expected: Vec<u8>,
    pub rqrr: Run,
    pub quircs: Run,
}

pub struct RobustResult {
    pub name: String,
    pub rqrr: Run,
    pub quircs: Run,
}

pub fn render(
    synthetic: &[CaseResult],
    fixtures: &[FixtureResult],
    two_code: &[TwoCodeResult],
    flipped: &[FlipResult],
    robust: &[RobustResult],
) -> String {
    let mut out = String::new();
    out.push_str("# QR decoder evaluation\n");
    out.push_str("rqrr 0.11.0 · quircs 0.10.3 · encoder qrcode 0.14.1\n\n");
    summary(&mut out, synthetic, flipped, fixtures, robust);
    byte_fidelity(&mut out, synthetic);
    by_degradation(&mut out, synthetic);
    fixtures_section(&mut out, fixtures);
    two_codes(&mut out, two_code);
    flipped_section(&mut out, flipped);
    robustness(&mut out, robust);
    findings(&mut out, synthetic, fixtures, flipped, robust);
    out
}

fn summary(
    out: &mut String,
    synthetic: &[CaseResult],
    flipped: &[FlipResult],
    fixtures: &[FixtureResult],
    robust: &[RobustResult],
) {
    let mut syn = [[0usize; 6]; 2];
    let mut ms = [Vec::new(), Vec::new()];
    for case in synthetic {
        let a = classify(&case.rqrr, case.expected.as_deref());
        let b = classify(&case.quircs, case.expected.as_deref());
        syn[0][a.index()] += 1;
        syn[1][b.index()] += 1;
        ms[0].push(case.rqrr.ms);
        ms[1].push(case.quircs.ms);
    }
    let total = synthetic.len();

    let mut flip_wrong = [0usize; 2];
    for case in flipped {
        if classify(&case.rqrr, Some(&case.expected)) == Outcome::Wrong {
            flip_wrong[0] += 1;
        }
        if classify(&case.quircs, Some(&case.expected)) == Outcome::Wrong {
            flip_wrong[1] += 1;
        }
    }

    let mut fix_exact = [0usize; 2];
    let mut fix_total = 0usize;
    for fixture in fixtures.iter().filter(|f| f.fixture.expected.is_some()) {
        fix_total += 1;
        if classify(&fixture.as_is.0, fixture.fixture.expected.as_deref()) == Outcome::Exact {
            fix_exact[0] += 1;
        }
        if classify(&fixture.as_is.1, fixture.fixture.expected.as_deref()) == Outcome::Exact {
            fix_exact[1] += 1;
        }
    }

    let mut rob_panic = [0usize; 2];
    let mut rob_fp = [0usize; 2];
    let mut rob_max = [0.0f64; 2];
    for case in robust {
        for (i, run) in [&case.rqrr, &case.quircs].into_iter().enumerate() {
            let outcome = classify(run, None);
            if outcome == Outcome::Panic {
                rob_panic[i] += 1;
            }
            if outcome == Outcome::FalsePositive {
                rob_fp[i] += 1;
            }
            rob_max[i] = rob_max[i].max(run.ms);
        }
    }

    out.push_str("## Summary\n\n");
    out.push_str("| metric | rqrr | quircs |\n|---|---|---|\n");
    out.push_str(&format!("| synthetic Exact | {}/{} | {}/{} |\n", syn[0][0], total, syn[1][0], total));
    out.push_str(&format!("| synthetic Wrong | {} | {} |\n", syn[0][1], syn[1][1]));
    out.push_str(&format!("| synthetic NotFound | {} | {} |\n", syn[0][2], syn[1][2]));
    out.push_str(&format!("| synthetic Error | {} | {} |\n", syn[0][3], syn[1][3]));
    out.push_str(&format!("| synthetic Panic | {} | {} |\n", syn[0][4], syn[1][4]));
    out.push_str(&format!("| flipped-module Wrong | {} | {} |\n", flip_wrong[0], flip_wrong[1]));
    out.push_str(&format!(
        "| known-payload fixtures Exact | {}/{} | {}/{} |\n",
        fix_exact[0], fix_total, fix_exact[1], fix_total
    ));
    out.push_str(&format!("| robustness Panic | {} | {} |\n", rob_panic[0], rob_panic[1]));
    out.push_str(&format!("| robustness FalsePositive | {} | {} |\n", rob_fp[0], rob_fp[1]));
    out.push_str(&format!("| robustness max ms | {:.1} | {:.1} |\n", rob_max[0], rob_max[1]));
    out.push_str(&format!(
        "| synthetic median ms | {:.1} | {:.1} |\n",
        median(&mut ms[0]),
        median(&mut ms[1])
    ));
    out.push_str(&format!(
        "| synthetic max ms | {:.1} | {:.1} |\n",
        max_of(&ms[0]),
        max_of(&ms[1])
    ));
    out.push('\n');
}

fn byte_fidelity(out: &mut String, synthetic: &[CaseResult]) {
    out.push_str("## Byte fidelity (D1, EC M)\n\n");
    out.push_str("| payload | rqrr | rqrr bytes | quircs | quircs bytes | quircs type | quircs ECI |\n");
    out.push_str("|---|---|---|---|---|---|---|\n");
    for case in synthetic.iter().filter(|c| c.degradation == "D1" && c.ec == "M") {
        let a = classify(&case.rqrr, case.expected.as_deref());
        let b = classify(&case.quircs, case.expected.as_deref());
        let a_bytes = case
            .rqrr
            .decoded()
            .first()
            .map(|bytes| hex_prefix(bytes, 64))
            .unwrap_or_default();
        let b_bytes = case
            .quircs
            .decoded()
            .first()
            .map(|bytes| hex_prefix(bytes, 64))
            .unwrap_or_default();
        let (data_type, eci) = case
            .quircs
            .codes()
            .iter()
            .find_map(|code| match code {
                CodeOutcome::Decoded { info, .. } => Some((
                    info.data_type.clone().unwrap_or_default(),
                    info.eci.clone().unwrap_or_default(),
                )),
                CodeOutcome::Error(_) => None,
            })
            .unwrap_or_default();
        out.push_str(&format!(
            "| {} | {} | `{}` | {} | `{}` | {} | {} |\n",
            case.payload_id,
            a.label(),
            a_bytes,
            b.label(),
            b_bytes,
            data_type,
            eci
        ));
    }
    out.push('\n');
}

fn by_degradation(out: &mut String, synthetic: &[CaseResult]) {
    out.push_str("## By degradation\n\n");
    out.push_str("| degradation | rqrr Exact/total | quircs Exact/total |\n|---|---|---|\n");
    for d in 1..=27 {
        let id = format!("D{d}");
        let mut a = 0usize;
        let mut b = 0usize;
        let mut n = 0usize;
        for case in synthetic.iter().filter(|c| c.degradation == id) {
            n += 1;
            if classify(&case.rqrr, case.expected.as_deref()) == Outcome::Exact {
                a += 1;
            }
            if classify(&case.quircs, case.expected.as_deref()) == Outcome::Exact {
                b += 1;
            }
        }
        out.push_str(&format!("| {id} | {a}/{n} | {b}/{n} |\n"));
    }
    out.push('\n');
}

fn fixtures_section(out: &mut String, fixtures: &[FixtureResult]) {
    out.push_str("## Fixtures\n\n");
    out.push_str("| file | format | rqrr as-is | rqrr blur | rqrr rotate | quircs as-is | quircs blur | quircs rotate |\n");
    out.push_str("|---|---|---|---|---|---|---|---|\n");
    for fixture in fixtures {
        let cell = |run: &Run| classify(run, fixture.fixture.expected.as_deref()).label();
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} |\n",
            fixture.fixture.file,
            fixture.fixture.format,
            cell(&fixture.as_is.0),
            cell(&fixture.blur.0),
            cell(&fixture.rotate.0),
            cell(&fixture.as_is.1),
            cell(&fixture.blur.1),
            cell(&fixture.rotate.1),
        ));
    }
    out.push('\n');

    let unknown: Vec<&FixtureResult> = fixtures
        .iter()
        .filter(|f| f.fixture.expected.is_none())
        .collect();
    if !unknown.is_empty() {
        out.push_str("### Unknown payloads\n\n");
        for fixture in unknown {
            let a = fixture
                .as_is
                .0
                .decoded()
                .first()
                .map(|bytes| hex(bytes))
                .unwrap_or_else(|| "-".to_string());
            let b = fixture
                .as_is
                .1
                .decoded()
                .first()
                .map(|bytes| hex(bytes))
                .unwrap_or_else(|| "-".to_string());
            out.push_str(&format!(
                "- `{}`: rqrr `{}`, quircs `{}`, agree: {}\n",
                fixture.fixture.file,
                a,
                b,
                a == b
            ));
        }
        out.push('\n');
    }
}

fn two_codes(out: &mut String, cases: &[TwoCodeResult]) {
    out.push_str("## Two codes in one frame\n\n");
    for case in cases {
        out.push_str(&format!("### {}\n\n", case.name));
        for (label, run) in [("rqrr", &case.rqrr), ("quircs", &case.quircs)] {
            let decoded = run.decoded();
            out.push_str(&format!("- {label}: {} code(s) returned", run.codes().len()));
            for (i, expected) in case.expected.iter().enumerate() {
                let found = decoded.iter().any(|bytes| *bytes == expected.as_slice());
                out.push_str(&format!(
                    "; expected {} {}",
                    i + 1,
                    if found { "found" } else { "missing" }
                ));
            }
            let unexpected = decoded
                .iter()
                .filter(|bytes| !case.expected.iter().any(|expected| **bytes == expected.as_slice()))
                .count();
            out.push_str(&format!("; unexpected payloads {unexpected}"));
            out.push('\n');
        }
        out.push('\n');
    }
}

fn flipped_section(out: &mut String, cases: &[FlipResult]) {
    out.push_str("## Flipped modules\n\n");
    out.push_str("| case | rqrr Exact | rqrr Wrong | rqrr NotFound | rqrr Error | quircs Exact | quircs Wrong | quircs NotFound | quircs Error |\n");
    out.push_str("|---|---|---|---|---|---|---|---|---|\n");
    let mut groups: Vec<(String, [usize; 6], [usize; 6])> = Vec::new();
    for case in cases {
        let index = match groups.iter().position(|(group, _, _)| *group == case.group) {
            Some(index) => index,
            None => {
                groups.push((case.group.clone(), [0; 6], [0; 6]));
                groups.len() - 1
            }
        };
        let a = classify(&case.rqrr, Some(&case.expected));
        let b = classify(&case.quircs, Some(&case.expected));
        groups[index].1[a.index()] += 1;
        groups[index].2[b.index()] += 1;
    }
    for (group, a, b) in &groups {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            group, a[0], a[1], a[2], a[3], b[0], b[1], b[2], b[3]
        ));
    }
    out.push('\n');
}

fn robustness(out: &mut String, cases: &[RobustResult]) {
    out.push_str("## Robustness\n\n");
    out.push_str("| case | rqrr | rqrr ms | quircs | quircs ms |\n|---|---|---|---|---|\n");
    for case in cases {
        let a = classify(&case.rqrr, None);
        let b = classify(&case.quircs, None);
        out.push_str(&format!(
            "| {} | {} | {:.1} | {} | {:.1} |\n",
            case.name,
            a.label(),
            case.rqrr.ms,
            b.label(),
            case.quircs.ms
        ));
    }
    out.push('\n');
}

fn findings(
    out: &mut String,
    synthetic: &[CaseResult],
    fixtures: &[FixtureResult],
    flipped: &[FlipResult],
    robust: &[RobustResult],
) {
    let mut items = Vec::new();
    for case in synthetic {
        for (label, run) in [("rqrr", &case.rqrr), ("quircs", &case.quircs)] {
            let outcome = classify(run, case.expected.as_deref());
            if outcome == Outcome::Wrong {
                items.push(format!("Wrong: {} ({label})", case.name));
            }
            if outcome == Outcome::Panic {
                items.push(format!("Panic: {} ({label})", case.name));
            }
            if run.ms > 2000.0 {
                items.push(format!("Slow: {} ({label}) {:.0} ms", case.name, run.ms));
            }
        }
    }
    for case in flipped {
        for (label, run) in [("rqrr", &case.rqrr), ("quircs", &case.quircs)] {
            let outcome = classify(run, Some(&case.expected));
            if outcome == Outcome::Wrong {
                items.push(format!("Wrong: {} ({label})", case.name));
            }
            if outcome == Outcome::Panic {
                items.push(format!("Panic: {} ({label})", case.name));
            }
            if run.ms > 2000.0 {
                items.push(format!("Slow: {} ({label}) {:.0} ms", case.name, run.ms));
            }
        }
    }
    for fixture in fixtures {
        for (variant, (a, b)) in [
            ("as-is", &fixture.as_is),
            ("blur", &fixture.blur),
            ("rotate", &fixture.rotate),
        ] {
            for (label, run) in [("rqrr", a), ("quircs", b)] {
                let outcome = classify(run, fixture.fixture.expected.as_deref());
                if outcome == Outcome::Wrong {
                    items.push(format!("Wrong: {} {variant} ({label})", fixture.fixture.file));
                }
                if outcome == Outcome::Panic {
                    items.push(format!("Panic: {} {variant} ({label})", fixture.fixture.file));
                }
                if run.ms > 2000.0 {
                    items.push(format!(
                        "Slow: {} {variant} ({label}) {:.0} ms",
                        fixture.fixture.file, run.ms
                    ));
                }
            }
        }
    }
    for case in robust {
        for (label, run) in [("rqrr", &case.rqrr), ("quircs", &case.quircs)] {
            let outcome = classify(run, None);
            if outcome == Outcome::FalsePositive {
                items.push(format!("FalsePositive: {} ({label})", case.name));
            }
            if outcome == Outcome::Panic {
                items.push(format!("Panic: {} ({label})", case.name));
            }
            if run.ms > 2000.0 {
                items.push(format!("Slow: {} ({label}) {:.0} ms", case.name, run.ms));
            }
        }
    }

    out.push_str("## Findings\n\n");
    if items.is_empty() {
        out.push_str("None.\n");
    } else {
        for item in items {
            out.push_str(&format!("- {item}\n"));
        }
    }
}

fn hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

fn hex_prefix(bytes: &[u8], limit: usize) -> String {
    let take = bytes.len().min(limit);
    hex(&bytes[..take])
}

fn median(values: &mut [f64]) -> f64 {
    if values.is_empty() {
        return 0.0;
    }
    values.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    values[values.len() / 2]
}

fn max_of(values: &[f64]) -> f64 {
    values.iter().copied().fold(0.0, f64::max)
}
