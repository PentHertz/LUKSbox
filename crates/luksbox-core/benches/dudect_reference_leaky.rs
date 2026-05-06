// Reference dudect bench: a deliberately-leaky function.
//
// Purpose: prove the dudect tooling actually detects timing leaks on
// this machine. If this bench reports "constant-time = PASS", the
// tooling is misconfigured and we shouldn't trust the other dudect
// results. dudect MUST report a |t-statistic| above the leak threshold
// (typically > 4.5) for this function.
//
// Run with: cargo bench --bench dudect_reference_leaky -p luksbox-core

use luksbox_ct_bench::rand::prelude::*;
use luksbox_ct_bench::{BenchRng, Class, CtRunner, ctbench_main};

/// Naive byte-by-byte comparison with early return. Classic timing-leak
/// pattern: returns faster when the first differing byte is later in
/// the input.
fn naive_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    for i in 0..a.len() {
        if a[i] != b[i] {
            return false;
        }
    }
    true
}

fn naive_compare_bench(runner: &mut CtRunner, rng: &mut BenchRng) {
    const N: usize = 100_000;
    let target = vec![0xAAu8; 32];

    // Class Left:  inputs that differ at byte 0  (returns immediately)
    // Class Right: inputs that differ at byte 31 (returns after 31 iterations)
    // The two classes have very different runtime; dudect must detect this.
    let mut inputs = Vec::with_capacity(N);
    let mut classes = Vec::with_capacity(N);
    for _ in 0..N {
        let mut buf = target.clone();
        if rng.random::<bool>() {
            buf[0] ^= 0x01;
            inputs.push(buf);
            classes.push(Class::Left);
        } else {
            buf[31] ^= 0x01;
            inputs.push(buf);
            classes.push(Class::Right);
        }
    }

    for (input, class) in inputs.into_iter().zip(classes.into_iter()) {
        runner.run_one(class, || {
            // Force the compiler to not optimize the call away.
            std::hint::black_box(naive_compare(
                std::hint::black_box(&input),
                std::hint::black_box(&target),
            ))
        });
    }
}

ctbench_main!(naive_compare_bench);
