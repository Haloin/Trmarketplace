//! Laplace mechanism for ε-differential privacy on timestamps and counts.

use rand::Rng;


pub const DEFAULT_EPSILON: f64 = 1.0;


pub const BUCKET_SENSITIVITY: f64 = 21600.0;


pub fn laplace_noise(scale: f64) -> f64 {
    if scale <= 0.0 {
        return 0.0;
    }
    let mut rng = rand::rngs::OsRng;
    let u: f64 = rng.gen();
    // Map u to symmetric uniform around 0 in (-0.5, 0.5).
    let s = u - 0.5;
    // log term. 1 - 2|s| ∈ (0, 1], log is in (-inf, 0].
    // To avoid log(0), clamp below to a small positive epsilon.
    let log_arg = (1.0 - 2.0 * s.abs()).max(f64::MIN_POSITIVE);
    let sign = if s >= 0.0 { 1.0 } else { -1.0 };
    -scale * sign * log_arg.ln()
}

/// Laplace noise offset for the given privacy budget and sensitivity.
pub fn noisy_offset(epsilon: f64, sensitivity: f64) -> i64 {
    if epsilon <= 0.0 {
        // epsilon → 0 would require infinite noise; clamp to integer zero.
        return 0;
    }
    let scale = sensitivity / epsilon;
    laplace_noise(scale).round() as i64
}

/// Add Laplace noise to a Unix timestamp for differential privacy.
///
/// Useful for obfuscating bucket edges, query log timestamps, or any
/// timing metadata visible to the server.
pub fn noisy_timestamp(timestamp: i64, epsilon: f64, sensitivity: f64) -> i64 {
    timestamp.saturating_add(noisy_offset(epsilon, sensitivity))
}

/// Quantize a noisy timestamp to a 6h bucket, preserving differential
/// privacy guarantees on the bucket value.
pub fn noisy_bucket(timestamp: i64, epsilon: f64) -> i64 {
    let noisy = noisy_timestamp(timestamp, epsilon, BUCKET_SENSITIVITY);
    // floor to 6h
    floor_to_bucket(noisy, 21600)
}

fn floor_to_bucket(timestamp: i64, bucket_size: i64) -> i64 {
    (timestamp / bucket_size) * bucket_size
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_laplace_noise_zero_scale_returns_zero() {
        assert_eq!(laplace_noise(0.0), 0.0);
        assert_eq!(laplace_noise(-1.0), 0.0);
    }

    #[test]
    fn test_laplace_noise_around_zero() {
        // Sample 1000 values; mean should be approximately 0.
        let n = 1000;
        let sum: f64 = (0..n).map(|_| laplace_noise(1.0)).sum();
        let mean = sum / n as f64;
        // With n=1000 and scale=1, mean should be within 0.5 of 0
        // (rough heuristic; Laplace has infinite variance but mean is 0).
        assert!(mean.abs() < 0.5,
            "Laplace mean over 1000 samples should be near 0, got {mean}");
    }

    #[test]
    fn test_laplace_noise_magnitude_proportional_to_scale() {
        // Larger scale → larger noise.
        let samples_small: Vec<f64> = (0..500).map(|_| laplace_noise(1.0).abs()).collect();
        let samples_large: Vec<f64> = (0..500).map(|_| laplace_noise(100.0).abs()).collect();
        let mean_small: f64 = samples_small.iter().sum::<f64>() / 500.0;
        let mean_large: f64 = samples_large.iter().sum::<f64>() / 500.0;
        // |mean| ≈ scale for Laplace.
        assert!(mean_large > 10.0 * mean_small,
            "Scale=100 noise should be 10x larger than scale=1; got small={mean_small}, large={mean_large}");
    }

    #[test]
    fn test_noisy_offset_finite() {
        let epsilon = 1.0;
        let sensitivity = 21600.0;
        for _ in 0..100 {
            let n = noisy_offset(epsilon, sensitivity);
            // Scale = 21600, so values are typically in [-100_000, 100_000].
            assert!(n.abs() < 1_000_000_000,
                "noisy_offset returned unexpectedly large value: {n}");
        }
    }

    #[test]
    fn test_noisy_offset_zero_epsilon_returns_zero() {
        assert_eq!(noisy_offset(0.0, 21600.0), 0);
        assert_eq!(noisy_offset(-1.0, 21600.0), 0);
    }

    #[test]
    fn test_noisy_timestamp_saturates() {
        let result = noisy_timestamp(i64::MAX, 1.0, 21600.0);
        // Should saturate rather than overflow.
        assert!(result > 0);
    }

    #[test]
    fn test_noisy_bucket_quantizes_to_6h() {
        let ts: i64 = 1_747_000_000; // arbitrary
        let bucketed = noisy_bucket(ts, 1.0);
        let bucket_size: i64 = 21600;
        assert_eq!(bucketed % bucket_size, 0,
            "noisy_bucket result {bucketed} must be a 6h multiple");
    }

    #[test]
    fn test_noisy_offset_distribution_properties() {
        // Verify that samples of noisy_offset are distributed per Laplace:
        //   E[|X|] = scale = sensitivity / epsilon
        // For sensitivity=21600, ε=1: E[|X|] ≈ 21600.
        let n = 1000;
        let sum_abs: f64 = (0..n)
            .map(|_| noisy_offset(1.0, 21600.0).unsigned_abs() as f64)
            .sum();
        let mean_abs = sum_abs / n as f64;
        // Allow 50% deviation due to heavy-tailed distribution.
        assert!(mean_abs > 10_000.0 && mean_abs < 40_000.0,
            "Expected mean |noise| ≈ 21600, got {mean_abs}");
    }
}
