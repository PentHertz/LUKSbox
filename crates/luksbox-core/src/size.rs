// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Penthertz <https://penthertz.com> (https://x.com/PentHertz)

//! Human-readable byte sizes, shared by the CLI, the wizard and the GUI
//! so that `6G` means the same everywhere.
//!
//! Every unit is 1024-based: `K`, `M`, `G`, `T`, each with or without a
//! trailing `B` or `iB` (`6G` = `6GB` = `6GiB` = 6 x 1024^3 bytes),
//! case-insensitive. That matches how LUKSbox displays sizes
//! ([`format_size`]), so a value typed back in means what was shown.

use std::fmt;

pub const KIB: u64 = 1024;
pub const MIB: u64 = 1024 * KIB;
pub const GIB: u64 = 1024 * MIB;
pub const TIB: u64 = 1024 * GIB;

/// Why [`parse_size`] rejected its input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SizeParseError {
    Empty,
    /// Not a number, or a fraction of a byte (`1.5` without a unit).
    InvalidNumber(String),
    UnknownUnit(String),
    TooLarge,
}

impl fmt::Display for SizeParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty size"),
            Self::InvalidNumber(n) => write!(
                f,
                "'{n}' is not a size; use a number with an optional unit, e.g. 6G, 500M, 1.5G"
            ),
            Self::UnknownUnit(u) => write!(f, "unknown unit '{u}'; use K, M, G or T (e.g. 6G)"),
            Self::TooLarge => write!(f, "size too large"),
        }
    }
}

impl std::error::Error for SizeParseError {}

/// Parse a size such as `6G`, `62M`, `1.5 GiB`, `500k` or `6442450944`
/// (a plain number is bytes). `0`, `unlimited`, `none` and `off` all give
/// 0, which size options use for "no limit". Fractions are rounded down
/// to whole bytes.
pub fn parse_size(input: &str) -> Result<u64, SizeParseError> {
    let s = input.trim();
    if s.is_empty() {
        return Err(SizeParseError::Empty);
    }
    if ["unlimited", "none", "off"]
        .iter()
        .any(|w| s.eq_ignore_ascii_case(w))
    {
        return Ok(0);
    }
    let split = s
        .find(|c: char| !(c.is_ascii_digit() || c == '.'))
        .unwrap_or(s.len());
    let (number, unit) = (&s[..split], s[split..].trim_start());
    let multiplier = match unit.to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => KIB,
        "m" | "mb" | "mib" => MIB,
        "g" | "gb" | "gib" => GIB,
        "t" | "tb" | "tib" => TIB,
        _ => return Err(SizeParseError::UnknownUnit(unit.to_string())),
    };
    let invalid = || SizeParseError::InvalidNumber(number.to_string());
    let (int_part, frac_part) = match number.split_once('.') {
        Some((i, f)) => (i, f),
        None => (number, ""),
    };
    let digits_only = |p: &str| p.bytes().all(|b| b.is_ascii_digit());
    if (int_part.is_empty() && frac_part.is_empty())
        || !digits_only(int_part)
        || !digits_only(frac_part)
        || (number.contains('.') && multiplier == 1)
    {
        return Err(invalid());
    }
    let int: u128 = if int_part.is_empty() {
        0
    } else {
        int_part.parse().map_err(|_| SizeParseError::TooLarge)?
    };
    let mut bytes = int
        .checked_mul(u128::from(multiplier))
        .ok_or(SizeParseError::TooLarge)?;
    if !frac_part.is_empty() {
        // At most 18 fraction digits matter for a u64 byte count; more
        // would only overflow the u128 below.
        let frac = &frac_part[..frac_part.len().min(18)];
        let numerator: u128 = frac.parse().map_err(|_| invalid())?;
        let denominator = 10u128.pow(frac.len() as u32);
        bytes += numerator * u128::from(multiplier) / denominator;
    }
    u64::try_from(bytes).map_err(|_| SizeParseError::TooLarge)
}

/// `bytes` for people: 1024-based with one decimal (`6.0 GB`, `64.0 MB`),
/// plain bytes below 1 KB (`512 B`). The labels are KB/MB/GB/TB, as the
/// GUI and most file managers show 1024-based sizes.
pub fn format_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// `bytes` with thousands separators (`6,442,450,944`), for echoing back
/// exactly what a size was understood as.
pub fn format_bytes_exact(bytes: u64) -> String {
    let digits = bytes.to_string();
    let mut out = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

/// `6.0 GB (6,442,450,944 bytes)`: [`format_size`] plus the exact byte
/// count, for echoing back what a typed size was understood as.
pub fn describe_size(bytes: u64) -> String {
    if bytes < KIB {
        format_size(bytes)
    } else {
        format!(
            "{} ({} bytes)",
            format_size(bytes),
            format_bytes_exact(bytes)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn units_are_1024_based_with_or_without_b_or_ib() {
        for s in ["6G", "6g", "6GB", "6gb", "6GiB", "6 G", " 6 GiB "] {
            assert_eq!(parse_size(s), Ok(6 * GIB), "{s}");
        }
        assert_eq!(parse_size("62M"), Ok(62 * MIB));
        assert_eq!(parse_size("500k"), Ok(500 * KIB));
        assert_eq!(parse_size("2T"), Ok(2 * TIB));
        assert_eq!(parse_size("4096B"), Ok(4096));
    }

    #[test]
    fn plain_numbers_are_bytes_and_zero_words_mean_unlimited() {
        assert_eq!(parse_size("6442450944"), Ok(6 * GIB));
        for s in ["0", "unlimited", "None", "OFF", "0G"] {
            assert_eq!(parse_size(s), Ok(0), "{s}");
        }
    }

    #[test]
    fn decimals_round_down_to_whole_bytes() {
        assert_eq!(parse_size("1.5G"), Ok(GIB + GIB / 2));
        assert_eq!(parse_size(".5M"), Ok(MIB / 2));
        assert_eq!(parse_size("0.1K"), Ok(102)); // 102.4 bytes
        assert_eq!(parse_size("2.G"), Ok(2 * GIB));
    }

    #[test]
    fn rejects_garbage_with_a_useful_error() {
        assert_eq!(parse_size(""), Err(SizeParseError::Empty));
        assert_eq!(parse_size("  "), Err(SizeParseError::Empty));
        assert!(matches!(parse_size("6X"), Err(SizeParseError::UnknownUnit(u)) if u == "X"));
        assert!(matches!(
            parse_size("6 GBs"),
            Err(SizeParseError::UnknownUnit(_))
        ));
        assert!(matches!(
            parse_size("G"),
            Err(SizeParseError::InvalidNumber(_))
        ));
        assert!(matches!(
            parse_size("1.2.3G"),
            Err(SizeParseError::InvalidNumber(_))
        ));
        assert!(matches!(
            parse_size("-5G"),
            Err(SizeParseError::UnknownUnit(_))
        ));
        // A fraction of a byte is a mistake, not something to round.
        assert!(matches!(
            parse_size("1.5"),
            Err(SizeParseError::InvalidNumber(_))
        ));
        assert_eq!(
            parse_size("99999999999999999999T"),
            Err(SizeParseError::TooLarge)
        );
        assert_eq!(parse_size("17179869184T"), Err(SizeParseError::TooLarge));
    }

    #[test]
    fn format_matches_what_parse_reads_back() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(1023), "1023 B");
        assert_eq!(format_size(64 * MIB), "64.0 MB");
        assert_eq!(format_size(6 * GIB), "6.0 GB");
        assert_eq!(format_size(GIB + GIB / 2), "1.5 GB");
        assert_eq!(format_size(3 * TIB), "3.0 TB");
        assert_eq!(parse_size(&format_size(6 * GIB)), Ok(6 * GIB));
    }

    #[test]
    fn exact_bytes_have_thousands_separators() {
        assert_eq!(format_bytes_exact(0), "0");
        assert_eq!(format_bytes_exact(999), "999");
        assert_eq!(format_bytes_exact(1000), "1,000");
        assert_eq!(format_bytes_exact(6 * GIB), "6,442,450,944");
        assert_eq!(describe_size(6 * GIB), "6.0 GB (6,442,450,944 bytes)");
        assert_eq!(describe_size(512), "512 B");
    }
}
