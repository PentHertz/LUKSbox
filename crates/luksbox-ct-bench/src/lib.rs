// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com>

//! Tiny constant-time benchmark runner. Drop-in API replacement for
//! the relevant subset of `dudect-bencher 0.7` (which we used to depend
//! on, but which transitively pulls in `clap 2.34`, `atty`, and
//! `ansi_term`, all unmaintained per RUSTSEC-2021-0139,
//! RUSTSEC-2024-0375, and RUSTSEC-2021-0145).
//!
//! Implements the **DudeCT** statistical test from Reparaz, Balasch,
//! and Verbauwhede, "Dude, is my code constant time?" (DATE 2017):
//!
//!  1. Run many measurements of the function under test, each tagged
//!     `Class::Left` or `Class::Right`.
//!  2. Time each call (here via `std::time::Instant`; the original
//!     paper recommends `RDTSC` on x86 but `Instant` is portable and
//!     adequate for the leakage thresholds we care about).
//!  3. Compute Welch's t-test between the two timing distributions.
//!  4. Report `|t|`. The conventional threshold is **|t| > 4.5** =
//!     statistically detectable timing dependence, which on a
//!     correctly-implemented constant-time primitive should not
//!     occur.
//!
//! The API mirrors `dudect-bencher`'s public surface so the existing
//! benches (`crates/luksbox-core/benches/dudect_*.rs`) compile
//! unchanged after a `use` swap:
//!
//! ```ignore
//! use luksbox_ct_bench::{BenchRng, Class, CtRunner, ctbench_main};
//! use luksbox_ct_bench::rand::prelude::*;   // re-export of `rand`
//!
//! fn my_bench(runner: &mut CtRunner, rng: &mut BenchRng) {
//!     for _ in 0..50_000 {
//!         let class = if rng.random::<bool>() { Class::Left } else { Class::Right };
//!         runner.run_one(class, || {
//!             // ... work to measure ...
//!         });
//!     }
//! }
//!
//! ctbench_main!(my_bench);
//! ```

use std::time::Instant;

/// Re-export the `rand` crate so benches can `use luksbox_ct_bench::rand::prelude::*;`
/// (the same pattern dudect-bencher used).
pub use rand;

/// Which timing-class a sample belongs to. `Left` and `Right` are
/// arbitrary labels chosen by the bench: typically one represents
/// "early-fail" inputs and the other "late-fail" or "no-fail"
/// inputs. The DudeCT test asks whether the per-call running time
/// depends on the class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Left,
    Right,
}

/// Convenience alias matching `dudect-bencher`'s `BenchRng`. Any
/// `RngCore + 'static` would work; we pick `StdRng` for
/// determinism (seedable from a fixed seed in tests if needed).
pub type BenchRng = rand::rngs::StdRng;

/// Collects timing samples and runs the Welch t-test analysis when
/// `report` is called. The bench function gets a `&mut CtRunner`
/// and calls `run_one(class, closure)` once per measurement.
pub struct CtRunner {
    samples: Vec<(Class, u64)>,
}

impl CtRunner {
    fn new() -> Self {
        Self {
            samples: Vec::with_capacity(100_000),
        }
    }

    /// Time one execution of `f` and label the sample with `class`.
    /// `std::hint::black_box` should be used inside `f` to defeat
    /// optimisation; that's the bench author's responsibility, same
    /// as with dudect-bencher.
    pub fn run_one<F, R>(&mut self, class: Class, f: F)
    where
        F: FnOnce() -> R,
    {
        let start = Instant::now();
        let result = f();
        let elapsed = start.elapsed().as_nanos() as u64;
        // Force the result to be observed so the optimiser can't
        // hoist `f` out as dead code.
        std::hint::black_box(result);
        self.samples.push((class, elapsed));
    }

    fn report(&self, name: &str) {
        let (mut left, mut right): (Vec<u64>, Vec<u64>) = (Vec::new(), Vec::new());
        for &(c, t) in &self.samples {
            match c {
                Class::Left => left.push(t),
                Class::Right => right.push(t),
            }
        }
        if left.is_empty() || right.is_empty() {
            println!(
                "bench {name}: skipped (need samples in BOTH classes; got {} left, {} right)",
                left.len(),
                right.len()
            );
            return;
        }

        // Outlier crop: drop the top 5% of each class. The original
        // DudeCT paper uses a cap based on `q3 + 1.5*iqr`; a flat
        // percentile crop is simpler and produces qualitatively
        // similar results for the leakage thresholds we test.
        let crop = |v: &mut Vec<u64>| {
            v.sort_unstable();
            let keep = (v.len() as f64 * 0.95) as usize;
            v.truncate(keep);
        };
        crop(&mut left);
        crop(&mut right);

        let (lm, lv) = mean_var(&left);
        let (rm, rv) = mean_var(&right);
        let n_l = left.len() as f64;
        let n_r = right.len() as f64;
        // Welch's t-statistic.
        let denom = (lv / n_l + rv / n_r).sqrt();
        let t = if denom > 0.0 { (lm - rm) / denom } else { 0.0 };
        let verdict = if t.abs() > 4.5 {
            "LEAK DETECTED (|t| > 4.5)"
        } else if t.abs() > 3.0 {
            "borderline (3.0 < |t| <= 4.5)"
        } else {
            "OK (|t| <= 3.0)"
        };
        println!(
            "bench {name}: n_left={} n_right={} mean_left={:.1}ns mean_right={:.1}ns t={:+.3}  {verdict}",
            left.len(),
            right.len(),
            lm,
            rm,
            t,
        );
    }
}

fn mean_var(v: &[u64]) -> (f64, f64) {
    let n = v.len() as f64;
    let mean: f64 = v.iter().map(|&x| x as f64).sum::<f64>() / n;
    let var: f64 = v
        .iter()
        .map(|&x| {
            let d = x as f64 - mean;
            d * d
        })
        .sum::<f64>()
        / (n - 1.0).max(1.0);
    (mean, var)
}

/// Bench-fn signature accepted by `ctbench_main!`. Mirrors dudect-bencher.
pub type BenchFn = fn(&mut CtRunner, &mut BenchRng);

/// Run a single bench function with a fresh runner and a freshly-seeded
/// RNG. Called by the macro-generated `main`. Public so a binary harness
/// can call it directly if the macro doesn't fit (we keep it `pub` for
/// API parity even though the macro is the recommended entry point).
pub fn run_bench(name: &str, f: BenchFn) {
    use rand::SeedableRng;
    let mut runner = CtRunner::new();
    // Seed with fixed-zero for reproducibility across runs. Bench
    // operators who want randomised seeding can wrap and pass their
    // own seeded RNG via `run_one` themselves.
    let mut rng = BenchRng::seed_from_u64(0xC0FFEE);
    f(&mut runner, &mut rng);
    runner.report(name);
}

/// Define a `main()` that runs each listed bench fn in turn.
/// Same signature as dudect-bencher: `ctbench_main!(name1, name2, ...)`.
#[macro_export]
macro_rules! ctbench_main {
    ($($f:ident),+ $(,)?) => {
        fn main() {
            $(
                $crate::run_bench(stringify!($f), $f);
            )+
        }
    };
}
