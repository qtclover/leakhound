/// Shannon entropy of a byte string, in bits per byte.
///
/// Random base64 lands around 5-6, random hex around 4, English words and
/// identifiers mostly below 3.5.
pub fn shannon(s: &[u8]) -> f64 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s {
        counts[b as usize] += 1;
    }
    let len = s.len() as f64;
    counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            -p * p.log2()
        })
        .sum()
}

#[cfg(test)]
mod tests {
    use super::shannon;

    #[test]
    fn empty_and_uniform_strings_have_zero_entropy() {
        assert_eq!(shannon(b""), 0.0);
        assert_eq!(shannon(b"aaaaaaaa"), 0.0);
    }

    #[test]
    fn two_equally_likely_symbols_give_one_bit() {
        assert!((shannon(b"abababab") - 1.0).abs() < 1e-9);
    }

    #[test]
    fn random_looking_strings_score_higher_than_words() {
        assert!(shannon(b"q8Zr2LmX0vTa7KdP") > shannon(b"passwordpassword"));
    }
}
