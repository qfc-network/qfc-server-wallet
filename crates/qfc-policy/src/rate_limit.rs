//! Token-bucket rate limiter.
//!
//! Pure-Rust, in-process. M3+ will offer a Redis-backed implementation
//! sharing the same trait when we have multi-process deployments. For now
//! one `TokenBucketLimiter` per `RuleSetPolicy` instance is enough
//! (each `WalletService` holds the policy).
//!
//! Clock injection: the limiter takes a `Clock` trait object so tests can
//! advance time deterministically without `tokio::time::pause` hacks. The
//! default `SystemClock` reads `SystemTime::now()`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use tokio::sync::Mutex;

/// Source of "current Unix ms" for the limiter. Implementors must return
/// non-decreasing values. The default `SystemClock` reads the OS clock;
/// tests use `ManualClock` to step time deterministically.
pub trait Clock: Send + Sync {
    /// Current wall-clock time in Unix milliseconds.
    fn now_unix_ms(&self) -> i64;
}

/// Default clock backed by `std::time::SystemTime`.
#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> i64 {
        let dur = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default();
        // Saturating cast: dates before 2262 fit in i64 ms.
        i64::try_from(dur.as_millis()).unwrap_or(i64::MAX)
    }
}

/// Manually-stepped clock for deterministic tests.
#[derive(Clone, Debug, Default)]
pub struct ManualClock {
    now_ms: Arc<std::sync::atomic::AtomicI64>,
}

impl ManualClock {
    /// Construct a manual clock starting at `start_ms`.
    #[must_use]
    pub fn new(start_ms: i64) -> Self {
        Self {
            now_ms: Arc::new(std::sync::atomic::AtomicI64::new(start_ms)),
        }
    }

    /// Advance the clock by `delta_ms` milliseconds.
    pub fn advance_ms(&self, delta_ms: i64) {
        self.now_ms
            .fetch_add(delta_ms, std::sync::atomic::Ordering::SeqCst);
    }

    /// Set the clock to an absolute value.
    pub fn set(&self, t_ms: i64) {
        self.now_ms.store(t_ms, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_unix_ms(&self) -> i64 {
        self.now_ms.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[derive(Clone, Copy, Debug)]
struct BucketState {
    tokens: f64,
    last_refill_unix_ms: i64,
}

/// In-process token-bucket limiter.
///
/// One `TokenBucketLimiter` typically backs every `RateLimit` rule in the
/// policy — the rule's `scope` field is folded into the bucket key, so
/// per-wallet, per-requester, and per-(wallet,requester) limits share the
/// same map without colliding.
pub struct TokenBucketLimiter {
    inner: Mutex<HashMap<String, BucketState>>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for TokenBucketLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBucketLimiter").finish_non_exhaustive()
    }
}

impl TokenBucketLimiter {
    /// New limiter with the system clock.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            clock: Arc::new(SystemClock),
        }
    }

    /// New limiter with an injected clock (tests).
    #[must_use]
    pub fn with_clock(clock: Arc<dyn Clock>) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            clock,
        }
    }

    /// Borrow the clock (useful for tests so they can `advance_ms` the
    /// same instance the limiter sees).
    #[must_use]
    pub fn clock(&self) -> Arc<dyn Clock> {
        self.clock.clone()
    }

    /// Try to consume one token for `key`, with a bucket of `capacity`
    /// tokens and a refill rate of `1` token per `refill_per_secs`
    /// seconds. Returns `true` if a token was consumed, `false` if the
    /// bucket was empty.
    ///
    /// `capacity == 0` always denies. `refill_per_secs == 0` means the
    /// bucket never refills naturally (single fixed budget).
    pub async fn try_acquire(&self, key: &str, capacity: u32, refill_per_secs: u32) -> bool {
        if capacity == 0 {
            return false;
        }

        let now_ms = self.clock.now_unix_ms();
        let cap_f = f64::from(capacity);

        let mut guard = self.inner.lock().await;
        let entry = guard.entry(key.to_string()).or_insert(BucketState {
            tokens: cap_f,
            last_refill_unix_ms: now_ms,
        });

        // Refill since last touch. `refill_per_secs == 0` means no
        // natural refill; tokens consumed are gone until process restart.
        if refill_per_secs > 0 {
            let dt_ms = (now_ms - entry.last_refill_unix_ms).max(0);
            #[allow(clippy::cast_precision_loss)]
            let dt = (dt_ms as f64) / 1000.0;
            let rate = 1.0 / f64::from(refill_per_secs);
            let refill = dt * rate;
            entry.tokens = (entry.tokens + refill).min(cap_f);
            entry.last_refill_unix_ms = now_ms;
        }

        if entry.tokens >= 1.0 {
            entry.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

impl Default for TokenBucketLimiter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn capacity_one_allows_then_denies() {
        let clock = Arc::new(ManualClock::new(0));
        let l = TokenBucketLimiter::with_clock(clock.clone());
        assert!(l.try_acquire("k", 1, 60).await);
        assert!(!l.try_acquire("k", 1, 60).await);
    }

    #[tokio::test]
    async fn refills_after_elapsed_time() {
        let clock = Arc::new(ManualClock::new(0));
        let l = TokenBucketLimiter::with_clock(clock.clone());
        // 5 tokens, refill 1 token every 60s.
        for _ in 0..5 {
            assert!(l.try_acquire("k", 5, 60).await);
        }
        assert!(!l.try_acquire("k", 5, 60).await);
        clock.advance_ms(60_000);
        // One token should have refilled.
        assert!(l.try_acquire("k", 5, 60).await);
        assert!(!l.try_acquire("k", 5, 60).await);
    }

    #[tokio::test]
    async fn refill_caps_at_capacity() {
        let clock = Arc::new(ManualClock::new(0));
        let l = TokenBucketLimiter::with_clock(clock.clone());
        // 2 tokens.
        assert!(l.try_acquire("k", 2, 60).await);
        assert!(l.try_acquire("k", 2, 60).await);
        assert!(!l.try_acquire("k", 2, 60).await);
        // Wait *way* longer than full refill window.
        clock.advance_ms(10_000_000);
        // Only `capacity` tokens, not more.
        assert!(l.try_acquire("k", 2, 60).await);
        assert!(l.try_acquire("k", 2, 60).await);
        assert!(!l.try_acquire("k", 2, 60).await);
    }

    #[tokio::test]
    async fn capacity_zero_always_denies() {
        let l = TokenBucketLimiter::with_clock(Arc::new(ManualClock::new(0)));
        assert!(!l.try_acquire("k", 0, 60).await);
    }

    #[tokio::test]
    async fn distinct_keys_isolated() {
        let clock = Arc::new(ManualClock::new(0));
        let l = TokenBucketLimiter::with_clock(clock);
        assert!(l.try_acquire("a", 1, 60).await);
        assert!(!l.try_acquire("a", 1, 60).await);
        // `b` should still have a full bucket.
        assert!(l.try_acquire("b", 1, 60).await);
    }

    #[tokio::test]
    async fn refill_per_secs_zero_no_natural_refill() {
        let clock = Arc::new(ManualClock::new(0));
        let l = TokenBucketLimiter::with_clock(clock.clone());
        assert!(l.try_acquire("k", 1, 0).await);
        clock.advance_ms(1_000_000);
        assert!(!l.try_acquire("k", 1, 0).await);
    }
}
