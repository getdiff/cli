//! In-memory counter store for aggregate policy limits.
//!
//! Tracks counters keyed by `{session_id}:{provider}:{counter_name}` with
//! configurable TTL. Used by `PolicyEvaluator` to enforce `daily_limit_cents`
//! and similar aggregate limits.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// A counter entry with a value and expiry.
#[derive(Debug, Clone)]
struct CounterEntry {
    value: i64,
    expires_at: Instant,
}

/// Thread-safe in-memory counter store with per-key TTL.
pub struct CounterStore {
    entries: Mutex<HashMap<String, CounterEntry>>,
    default_ttl: Duration,
}

impl CounterStore {
    /// Create a new counter store with the given default TTL.
    pub fn new(default_ttl: Duration) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            default_ttl,
        }
    }

    /// Create a counter store with 24-hour default TTL (typical for daily limits).
    pub fn daily() -> Self {
        Self::new(Duration::from_secs(86400))
    }

    /// Build a counter key from session, provider, and counter name.
    pub fn key(session_id: &str, provider: &str, counter_name: &str) -> String {
        format!("{}:{}:{}", session_id, provider, counter_name)
    }

    /// Get the current value for a key. Returns 0 if the key doesn't exist
    /// or has expired.
    pub fn get(&self, key: &str) -> i64 {
        let mut entries = self.entries.lock().unwrap();
        match entries.get(key) {
            Some(entry) if entry.expires_at > Instant::now() => entry.value,
            Some(_) => {
                // Expired — remove it.
                entries.remove(key);
                0
            }
            None => 0,
        }
    }

    /// Increment a counter by the given amount. Creates the entry with
    /// the default TTL if it doesn't exist. Returns the new value.
    pub fn increment(&self, key: &str, amount: i64) -> i64 {
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();

        let entry = entries.entry(key.to_string()).or_insert_with(|| CounterEntry {
            value: 0,
            expires_at: now + self.default_ttl,
        });

        // If expired, reset.
        if entry.expires_at <= now {
            entry.value = 0;
            entry.expires_at = now + self.default_ttl;
        }

        entry.value += amount;
        entry.value
    }

    /// Increment with a custom TTL (overrides default for this key if new).
    pub fn increment_with_ttl(&self, key: &str, amount: i64, ttl: Duration) -> i64 {
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();

        let entry = entries.entry(key.to_string()).or_insert_with(|| CounterEntry {
            value: 0,
            expires_at: now + ttl,
        });

        if entry.expires_at <= now {
            entry.value = 0;
            entry.expires_at = now + ttl;
        }

        entry.value += amount;
        entry.value
    }

    /// Remove expired entries. Called periodically to prevent unbounded growth.
    pub fn evict_expired(&self) -> usize {
        let mut entries = self.entries.lock().unwrap();
        let now = Instant::now();
        let before = entries.len();
        entries.retain(|_, entry| entry.expires_at > now);
        before - entries.len()
    }

    /// Number of active (non-expired) counters.
    pub fn len(&self) -> usize {
        let entries = self.entries.lock().unwrap();
        let now = Instant::now();
        entries.values().filter(|e| e.expires_at > now).count()
    }

    /// Whether the store has no active counters.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_counter_starts_at_zero() {
        let store = CounterStore::daily();
        assert_eq!(store.get("any:key:here"), 0);
    }

    #[test]
    fn test_increment_and_get() {
        let store = CounterStore::daily();
        let key = CounterStore::key("sess-1", "stripe", "daily_spend");

        assert_eq!(store.increment(&key, 500), 500);
        assert_eq!(store.get(&key), 500);
        assert_eq!(store.increment(&key, 300), 800);
        assert_eq!(store.get(&key), 800);
    }

    #[test]
    fn test_key_format() {
        let key = CounterStore::key("sess-1", "stripe", "daily_spend");
        assert_eq!(key, "sess-1:stripe:daily_spend");
    }

    #[test]
    fn test_expired_entries_return_zero() {
        let store = CounterStore::new(Duration::from_millis(1));
        let key = "test:expire:key";

        store.increment(key, 100);
        // Sleep past the TTL.
        std::thread::sleep(Duration::from_millis(10));
        assert_eq!(store.get(key), 0);
    }

    #[test]
    fn test_expired_entry_resets_on_increment() {
        let store = CounterStore::new(Duration::from_millis(1));
        let key = "test:reset:key";

        store.increment(key, 100);
        std::thread::sleep(Duration::from_millis(10));

        // Incrementing after expiry starts from 0.
        assert_eq!(store.increment(key, 50), 50);
    }

    #[test]
    fn test_evict_expired() {
        let store = CounterStore::new(Duration::from_millis(1));

        store.increment("a", 1);
        store.increment("b", 2);
        store.increment("c", 3);
        std::thread::sleep(Duration::from_millis(10));

        let evicted = store.evict_expired();
        assert_eq!(evicted, 3);
        assert!(store.is_empty());
    }

    #[test]
    fn test_len_excludes_expired() {
        let store = CounterStore::new(Duration::from_millis(1));

        store.increment("short-lived", 1);
        std::thread::sleep(Duration::from_millis(10));

        // Still in map but expired.
        assert_eq!(store.len(), 0);

        // Add a long-lived one.
        let long_store = CounterStore::daily();
        long_store.increment("long-lived", 1);
        assert_eq!(long_store.len(), 1);
    }

    #[test]
    fn test_multiple_providers_independent() {
        let store = CounterStore::daily();

        let k1 = CounterStore::key("sess", "stripe", "daily_spend");
        let k2 = CounterStore::key("sess", "github", "daily_spend");

        store.increment(&k1, 1000);
        store.increment(&k2, 500);

        assert_eq!(store.get(&k1), 1000);
        assert_eq!(store.get(&k2), 500);
    }

    #[test]
    fn test_increment_with_custom_ttl() {
        let store = CounterStore::daily();
        let key = "custom:ttl:key";

        let val = store.increment_with_ttl(key, 42, Duration::from_secs(3600));
        assert_eq!(val, 42);
        assert_eq!(store.get(key), 42);
    }
}
