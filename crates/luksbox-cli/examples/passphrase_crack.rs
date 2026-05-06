// Wordlist-based passphrase brute-forcer for LUKSbox vaults.
//
// Uses the actual `Container::open` path from `luksbox-format`, so a
// successful unlock here is equivalent to a successful unlock from
// the regular CLI - i.e. this measures the real attacker cost
// against your specific vault, not a synthetic Argon2id benchmark.
//
// Build:
//   cargo build --release -p luksbox-cli --example passphrase_crack
//
// Run:
//   ./target/release/examples/passphrase_crack \
//       --vault target.lbx \
//       --header target.hdr \           # optional, only if detached
//       --wordlist words.txt \
//       --threads 8 \
//       --report-every 100
//
// Internal cracking-cost analysis (threat model + bounds) is available on request to security@penthertz.com.

use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use clap::Parser;
use luksbox_format::container::{Container, UnlockMaterial};

#[derive(Parser, Debug)]
#[command(
    about = "Wordlist passphrase brute-forcer for a LUKSbox vault",
    long_about = "Iterates a wordlist and attempts Container::open against \
                  the vault for each candidate. Use this to measure how \
                  resistant your vault is to your candidate wordlist on \
                  your hardware. Internal cracking-cost analysis (threat model + bounds) is available on request to security@penthertz.com. \
                  full threat model."
)]
struct Args {
    /// Path to the .lbx vault file
    #[arg(long)]
    vault: PathBuf,

    /// Path to the .hdr detached header (omit if header is inline)
    #[arg(long)]
    header: Option<PathBuf>,

    /// Wordlist file (one passphrase per line; pass `-` for stdin)
    #[arg(long)]
    wordlist: String,

    /// Number of worker threads. Each thread consumes ~m_cost_kib RAM.
    /// Default: 1, because each Argon2id call uses 256 MiB at the
    /// interactive preset. Don't oversubscribe RAM.
    #[arg(long, default_value_t = 1)]
    threads: usize,

    /// Print a progress line every N candidates tried (across all threads)
    #[arg(long, default_value_t = 100)]
    report_every: u64,

    /// Stop after this many candidates if no match found (0 = no limit)
    #[arg(long, default_value_t = 0)]
    max_candidates: u64,
}

fn main() {
    let args = Args::parse();

    // Open the vault once to validate it exists + identify slot kinds.
    // We won't keep this Container; each worker calls Container::open
    // independently per attempt (since open is the cracking surface).
    eprintln!("[+] vault: {}", args.vault.display());
    if let Some(h) = &args.header {
        eprintln!("[+] header: {} (detached)", h.display());
    } else {
        eprintln!("[+] header: inline in vault file");
    }

    // Quick precondition check: open the vault file and read the header
    // so we can fail fast on bad paths / corrupted headers, without
    // burning a wordlist scan first.
    let header_path_for_open = args.header.clone();
    {
        // A clearly-wrong passphrase to provoke an UnlockFailed (not a
        // file-error). If the vault has no passphrase slots at all,
        // open returns NoMatchingKeyslot, which we surface.
        let probe = Container::open(
            &args.vault,
            header_path_for_open.as_deref(),
            UnlockMaterial::Passphrase(b"\x00\x00\x00\x00probe-not-a-real-passphrase\x00"),
        );
        match probe {
            Ok(_) => {
                eprintln!("[!] WARNING: probe with 'probe-not-a-real-passphrase' SUCCEEDED.");
                eprintln!(
                    "[!] Either the vault has a trivial passphrase or this tool is misconfigured."
                );
            }
            Err(e) => {
                eprintln!("[+] vault opens cleanly with rejection: {e:?}");
            }
        }
    }

    // Open the wordlist.
    let wordlist_reader: Box<dyn BufRead + Send> = if args.wordlist == "-" {
        Box::new(BufReader::new(std::io::stdin()))
    } else {
        Box::new(BufReader::new(
            File::open(&args.wordlist).expect("wordlist open"),
        ))
    };

    // Channel for candidate distribution. Bounded so we don't read the
    // whole wordlist into memory (some wordlists are GB-sized).
    let (tx, rx): (SyncSender<String>, Receiver<String>) = sync_channel(args.threads * 16);
    let rx = Arc::new(Mutex::new(rx));

    // Shared state.
    let found = Arc::new(Mutex::new(None::<String>));
    let stop = Arc::new(AtomicBool::new(false));
    let attempts = Arc::new(AtomicU64::new(0));
    let started = Instant::now();

    // Spawn worker threads.
    let mut workers = Vec::with_capacity(args.threads);
    for tid in 0..args.threads {
        let vault = args.vault.clone();
        let header = args.header.clone();
        let rx = Arc::clone(&rx);
        let found = Arc::clone(&found);
        let stop = Arc::clone(&stop);
        let attempts = Arc::clone(&attempts);
        let report_every = args.report_every;
        let max_candidates = args.max_candidates;
        workers.push(std::thread::spawn(move || {
            loop {
                if stop.load(Ordering::Relaxed) {
                    return;
                }
                let candidate = {
                    let lock = rx.lock().unwrap();
                    match lock.recv() {
                        Ok(c) => c,
                        Err(_) => return, // channel closed
                    }
                };

                let r = Container::open(
                    &vault,
                    header.as_deref(),
                    UnlockMaterial::Passphrase(candidate.as_bytes()),
                );
                let n = attempts.fetch_add(1, Ordering::Relaxed) + 1;
                if r.is_ok() {
                    *found.lock().unwrap() = Some(candidate.clone());
                    stop.store(true, Ordering::Relaxed);
                    eprintln!(
                        "\n[+] FOUND on tid {tid}: passphrase = {:?}  (after {} attempts)",
                        candidate, n
                    );
                    return;
                }
                if max_candidates > 0 && n >= max_candidates {
                    stop.store(true, Ordering::Relaxed);
                    return;
                }
                if n % report_every == 0 {
                    let secs = started.elapsed().as_secs_f64();
                    let rate = n as f64 / secs;
                    eprintln!("[+] tried {n} ({rate:.2} g/s, elapsed {secs:.0}s)");
                }
            }
        }));
    }

    // Reader thread: pump wordlist -> channel.
    let stop_reader = Arc::clone(&stop);
    let reader_handle = std::thread::spawn(move || {
        let mut sent = 0u64;
        for line in wordlist_reader.lines() {
            if stop_reader.load(Ordering::Relaxed) {
                break;
            }
            let line = match line {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[!] wordlist read error: {e}");
                    break;
                }
            };
            // Strip carriage returns / trailing whitespace; keep
            // intentional internal whitespace (passphrases CAN contain it).
            let candidate = line.trim_end_matches(['\r', '\n']).to_string();
            if candidate.is_empty() {
                continue;
            }
            if tx.send(candidate).is_err() {
                break; // workers gone
            }
            sent += 1;
        }
        drop(tx); // close channel; workers will exit after draining
        sent
    });

    let total_sent = reader_handle.join().unwrap();
    for w in workers {
        let _ = w.join();
    }

    let elapsed = started.elapsed();
    let n = attempts.load(Ordering::Relaxed);
    let rate = if elapsed.as_secs_f64() > 0.0 {
        n as f64 / elapsed.as_secs_f64()
    } else {
        0.0
    };
    eprintln!("\n=== Cracking session complete ===");
    eprintln!("Wordlist candidates dispatched: {total_sent}");
    eprintln!("Total open() attempts:          {n}");
    eprintln!(
        "Wall time:                      {:.1}s  ({:.2} g/s overall)",
        elapsed.as_secs_f64(),
        rate
    );
    let lock = found.lock().unwrap();
    match &*lock {
        Some(p) => {
            println!("FOUND: {p}");
            std::process::exit(0);
        }
        None => {
            eprintln!("Result:                         no match in wordlist");
            std::process::exit(1);
        }
    }
}
