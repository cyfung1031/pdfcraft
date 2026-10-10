//! `cargo xtask fuzz-measure`: bounded, deterministic measure-geometry fuzzing on stable Rust.
//!
//! Mutates synthetic content streams, then exercises content parsing, geometry extraction and
//! snapping without invoking the renderer or reading external corpus files.
//!
//! ```text
//! cargo xtask fuzz-measure [--iterations 1000] [--seed 1]
//! ```

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;

use anyhow::{Result, bail, ensure};

const DEFAULT_ITERATIONS: usize = 1_000;
const MAX_ITERATIONS: usize = 10_000;
const MAX_CONTENT_BYTES: usize = 16 * 1024;
const MAX_GEOMETRY_SEGMENTS: usize = 20_000;
const MAX_SNAP_TARGETS: usize = 2 * MAX_GEOMETRY_SEGMENTS + 12;

const SEEDS: &[&[u8]] = &[
    b"0 0 m 100 100 l S",
    b"q 1 0 0 1 10 20 cm 0 0 10 10 re S Q",
    b"0 0 m 20 100 80 -100 100 0 c S",
    b"1e308 1e308 m -1e308 -1e308 l S",
    b"BI /W 1 /H 1 /BPC 8 /CS /RGB ID \x00\xff\x7f EI",
    b"q q q Q Q cm m l c v y h re S n",
];
const TOKENS: &[&[u8]] = &[
    b" m ",
    b" l ",
    b" c ",
    b" v ",
    b" y ",
    b" re ",
    b" S ",
    b" f* ",
    b" q Q ",
    b" cm ",
    b" Do ",
    b" BI ID EI ",
    b" 1e308 ",
    b" -1e308 ",
    b" /BadName ",
    b" [1 2 (unterminated] ",
];

#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 { 0 } else { (self.next() % n as u64) as usize }
    }
}

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut data = seed.to_vec();
    let rounds = 1 + rng.below(8);
    for _ in 0..rounds {
        if data.is_empty() {
            data.extend_from_slice(b"0 0 m 10 10 l S");
        }
        let at = rng.below(data.len());
        match rng.below(6) {
            0 => data[at] ^= 1 << rng.below(8),
            1 => {
                let n = 1 + rng.below(64.min(data.len() - at));
                data.drain(at..at + n);
            }
            2 => {
                let token = TOKENS[rng.below(TOKENS.len())];
                data.splice(at..at, token.iter().copied());
            }
            3 => {
                let n = 1 + rng.below(128.min(data.len() - at));
                let duplicate = data[at..at + n].to_vec();
                let to = rng.below(data.len());
                data.splice(to..to, duplicate);
            }
            4 => {
                let byte = [rng.next() as u8];
                data.splice(at..at, byte);
            }
            _ => {
                let token = TOKENS[rng.below(TOKENS.len())];
                let end = at.saturating_add(1).min(data.len());
                data.splice(at..end, token.iter().copied());
            }
        }
        data.truncate(MAX_CONTENT_BYTES);
    }
    data
}

fn one_page_pdf(content: &[u8]) -> Vec<u8> {
    let stream = format!("<< /Length {} >>\nstream\n", content.len());
    let objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>".to_vec(),
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 612 792] >>".to_vec(),
        b"<< /Type /Page /Parent 2 0 R /Contents 4 0 R /Resources << >> >>".to_vec(),
        {
            let mut object = stream.into_bytes();
            object.extend_from_slice(content);
            object.extend_from_slice(b"\nendstream");
            object
        },
    ];
    let mut bytes = b"%PDF-1.7\n".to_vec();
    let mut offsets = Vec::with_capacity(objects.len());
    for (index, object) in objects.iter().enumerate() {
        offsets.push(bytes.len());
        bytes.extend_from_slice(format!("{} 0 obj\n", index + 1).as_bytes());
        bytes.extend_from_slice(object);
        bytes.extend_from_slice(b"\nendobj\n");
    }
    let xref = bytes.len();
    bytes.extend_from_slice(format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes());
    for offset in offsets {
        bytes.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    bytes.extend_from_slice(format!("trailer\n<< /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n", objects.len() + 1).as_bytes());
    bytes
}

fn finite(point: [f64; 2]) -> bool {
    point.into_iter().all(f64::is_finite)
}

fn exercise(content: &[u8]) -> Result<bool> {
    ensure!(content.len() <= MAX_CONTENT_BYTES, "generated content exceeded the byte cap");
    let parsed = pdfcraft_content::parse(content);
    ensure!(parsed.ops.len() <= content.len().saturating_add(1), "content parser produced too many operators");

    let doc = pdfcraft_cos::Document::open(Arc::new(one_page_pdf(content)))?;
    let geometry = pdfcraft_measure::snap::geometry(&doc, 0)?;
    ensure!(geometry.segments.len() <= MAX_GEOMETRY_SEGMENTS, "geometry exceeded the segment cap: {}", geometry.segments.len());
    ensure!(geometry.endpoints.len().saturating_add(geometry.midpoints.len()) <= MAX_SNAP_TARGETS, "geometry exceeded the snap-target cap");
    ensure!(geometry.segments.iter().flatten().copied().all(finite), "geometry contains a non-finite segment coordinate");
    ensure!(geometry.endpoints.iter().copied().all(finite), "geometry contains a non-finite endpoint");
    ensure!(geometry.midpoints.iter().copied().all(finite), "geometry contains a non-finite midpoint");

    let _dense = geometry.intersection_limited([0.0, 0.0], 10_000.0);
    let snap = geometry.snap([0.0, 0.0], 10_000.0, pdfcraft_measure::snap::SnapOptions::default())?;
    if let Some(hit) = snap {
        ensure!(finite(hit.point) && hit.distance.is_finite(), "snap result contains a non-finite value");
    }
    Ok(geometry.truncated)
}

fn usage() -> &'static str {
    "usage: cargo xtask fuzz-measure [--iterations 1..10000] [--seed N]"
}

pub fn run(args: &[String]) -> Result<()> {
    let mut iterations = DEFAULT_ITERATIONS;
    let mut seed = 1_u64;
    let mut index = 0;
    while index < args.len() {
        let flag = args[index].as_str();
        let value = args.get(index + 1).ok_or_else(|| anyhow::anyhow!(usage()))?;
        match flag {
            "--iterations" => iterations = value.parse()?,
            "--seed" => seed = value.parse()?,
            _ => bail!("unknown argument `{flag}`; {}", usage()),
        }
        index += 2;
    }
    ensure!((1..=MAX_ITERATIONS).contains(&iterations), "iterations must be between 1 and {MAX_ITERATIONS}");

    let mut seeds: Vec<Vec<u8>> = SEEDS.iter().map(|seed| seed.to_vec()).collect();
    let mut dense = Vec::with_capacity(MAX_CONTENT_BYTES);
    while dense.len() + 14 <= MAX_CONTENT_BYTES {
        dense.extend_from_slice(b"0 0 m 1 1 l S ");
    }
    seeds.push(dense);

    let mut rng = Rng(seed.max(1));
    for iteration in 0..iterations {
        let seed_index = rng.below(seeds.len());
        let content = mutate(&mut rng, &seeds[seed_index]);
        let result = catch_unwind(AssertUnwindSafe(|| exercise(&content)));
        match result {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => bail!("measure fuzz failure at iteration {iteration}, seed {seed}: {error:#}"),
            Err(_) => {
                let sample = String::from_utf8_lossy(&content[..content.len().min(256)]);
                bail!("measure fuzz panic at iteration {iteration}, seed {seed}, content bytes {}: {sample:?}", content.len());
            }
        }
    }
    let stress_curve = b"0 0 m 0 100000000 100000000 100000000 100000000 0 c S ".repeat(6);
    match catch_unwind(AssertUnwindSafe(|| exercise(&stress_curve))) {
        Ok(Ok(true)) => {}
        Ok(Ok(false)) => bail!("high-curvature geometry did not report its extraction cap"),
        Ok(Err(error)) => return Err(error.context("high-curvature segment-cap fixture")),
        Err(_) => bail!("measure fuzz panic in high-curvature segment-cap fixture"),
    }
    println!("measure fuzz: {iterations} cases and bounded segment-cap fixture passed (seed {seed}, max mutated content {MAX_CONTENT_BYTES} bytes)");
    Ok(())
}
