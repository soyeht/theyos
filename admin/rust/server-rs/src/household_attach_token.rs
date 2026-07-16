//! Short-lived single-use attach tokens for household terminal `WebSockets`.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64URL};
use rand::{RngCore, rngs::OsRng};

pub const HOUSEHOLD_ATTACH_TOKEN_TTL: Duration = Duration::from_secs(30);

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HouseholdAttachScope {
    pub household_id: String,
    pub container: String,
    pub session_id: String,
    pub actor_person_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MintedHouseholdAttachToken {
    pub token: String,
    pub expires_at: u64,
}

#[derive(Clone, Debug)]
struct HouseholdAttachTokenEntry {
    scope: HouseholdAttachScope,
    expires_at_instant: Instant,
}

pub struct HouseholdAttachTokenStore {
    inner: Mutex<HashMap<String, HouseholdAttachTokenEntry>>,
    ttl: Duration,
}

impl Default for HouseholdAttachTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl HouseholdAttachTokenStore {
    #[must_use]
    pub fn new() -> Self {
        Self::with_ttl(HOUSEHOLD_ATTACH_TOKEN_TTL)
    }

    #[must_use]
    pub fn with_ttl(ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(HashMap::new()),
            ttl,
        }
    }

    #[must_use]
    pub fn mint(&self, scope: HouseholdAttachScope) -> MintedHouseholdAttachToken {
        self.mint_with_ttl(scope, self.ttl)
    }

    #[must_use]
    pub fn mint_with_ttl(
        &self,
        scope: HouseholdAttachScope,
        ttl: Duration,
    ) -> MintedHouseholdAttachToken {
        let now = Instant::now();
        let expires_at_instant = now + ttl;
        let expires_at_unix = SystemTime::now()
            .checked_add(ttl)
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |d| d.as_secs());
        let token = generate_token();
        let entry = HouseholdAttachTokenEntry {
            scope,
            expires_at_instant,
        };

        let mut guard = self.lock_entries();
        cleanup_expired(&mut guard, now);
        guard.insert(token.clone(), entry);
        MintedHouseholdAttachToken {
            token,
            expires_at: expires_at_unix,
        }
    }

    #[must_use]
    pub fn consume(&self, token: &str) -> Option<HouseholdAttachScope> {
        let now = Instant::now();
        let mut guard = self.lock_entries();
        cleanup_expired(&mut guard, now);
        let entry = guard.remove(token)?;
        if entry.expires_at_instant <= now {
            return None;
        }
        Some(entry.scope)
    }

    /// Number of currently redeemable tokens, without exposing their values.
    ///
    /// This is deliberately suitable for route-level health and regression
    /// checks: a rejected request must not increase this count.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        let now = Instant::now();
        let mut guard = self.lock_entries();
        cleanup_expired(&mut guard, now);
        guard.len()
    }

    fn lock_entries(
        &self,
    ) -> std::sync::MutexGuard<'_, HashMap<String, HouseholdAttachTokenEntry>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

fn cleanup_expired(entries: &mut HashMap<String, HouseholdAttachTokenEntry>, now: Instant) {
    entries.retain(|_, entry| entry.expires_at_instant > now);
}

fn generate_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    B64URL.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    fn scope() -> HouseholdAttachScope {
        HouseholdAttachScope {
            household_id: "hh-alpha".to_string(),
            container: "picoclaw-alpha".to_string(),
            session_id: "ws-alpha".to_string(),
            actor_person_id: "person-alpha".to_string(),
        }
    }

    #[test]
    fn token_consumes_once_and_preserves_scope() {
        let store = HouseholdAttachTokenStore::new();
        let expected = scope();
        let minted = store.mint(expected.clone());

        assert!(!minted.token.is_empty());
        assert!(
            minted.token.len() >= 22,
            "base64url token should encode at least 128 bits"
        );
        assert_eq!(store.consume(&minted.token), Some(expected));
        assert_eq!(store.consume(&minted.token), None);
    }

    #[test]
    fn expired_token_fails_closed() {
        let store = HouseholdAttachTokenStore::new();
        let minted = store.mint_with_ttl(scope(), Duration::from_secs(0));

        assert_eq!(store.consume(&minted.token), None);
    }

    #[test]
    fn concurrent_consume_has_one_winner() {
        let store = Arc::new(HouseholdAttachTokenStore::new());
        let minted = store.mint(scope());
        let barrier = Arc::new(Barrier::new(2));
        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = Arc::clone(&store);
                let token = minted.token.clone();
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    store.consume(&token).is_some()
                })
            })
            .collect();

        let winners = handles
            .into_iter()
            .map(|handle| usize::from(handle.join().expect("consume thread")))
            .sum::<usize>();
        assert_eq!(winners, 1);
        assert_eq!(store.consume(&minted.token), None);
    }
}
