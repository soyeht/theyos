//! `PrevalidatedIngress<T>` scaffolding (Fila 1 item 5, CFX-1/RED-42).
//!
//! B-SESSAO v6 §2: the v4 bug was `authorize_mesh_peer(ingress, session,
//! ...)` accepting a *separate* ingress parameter alongside a session that
//! already embedded one — evidence from stream A could be paired with
//! stream B. The fix is an aggregate the adapter builds once, that a
//! constructor consumes by move and never re-exposes in pieces.
//!
//! **Hardened 2026-08-04, independent audit of `911409eb`:** `consume`
//! used to be `pub`, which meant *any* external caller — not just this
//! crate's own auth state machine — could unpack a `PrevalidatedIngress<T>`
//! back into its raw `(T, IngressEvidence)` and then call
//! [`PrevalidatedIngress::new`] again with a stream from one ingress and
//! evidence from a *different* one. That is exactly the v4 bug the type
//! exists to prevent, just moved one step later: the adapter can only
//! create the pair once, but nothing stopped a caller from taking it apart
//! and reassembling a mismatched one. `consume` is now `pub(crate)` — only
//! this crate's own `start_session` (the auth state machine) may take the
//! aggregate apart, and it does so internally, embedding the evidence in
//! whatever session type it returns rather than handing either piece back
//! out. `new` stays `pub`: the adapter (a different crate) legitimately
//! needs to construct the pair — v6 §11, CORE only trusts the adapter for
//! prefilter, never for identity, and construction is where that trust is
//! exercised, not extraction.

/// Evidence an adapter attaches to a stream it has already prefiltered
/// (e.g. accepted a TCP connection, matched some coarse allow-list). CORE
/// trusts this only for DoS/prefiltering, never for identity — v6 §11.
///
/// Concrete fields are the adapter's decision (Fila 3/4), not restated
/// here; `observed_at` is a placeholder shape, not a normative field list.
#[derive(Debug)]
pub struct IngressEvidence {
    pub observed_at: u64,
}

/// `stream` and `evidence` are inseparable from the moment the adapter
/// builds this: no `Clone`, no public accessor that returns one without
/// the other, and the only way to get either out —
/// [`consume`](Self::consume) — is `pub(crate)`, reachable only from this
/// crate's own `start_session`.
///
/// `PrevalidatedIngress<T>` derives no `Clone` impl, so cloning one — even
/// when `T` itself is `Clone` (`u32` is) — does not compile:
///
/// ```compile_fail
/// use mesh_session_core_rs::ingress::{PrevalidatedIngress, IngressEvidence};
/// let ingress = PrevalidatedIngress::new(42u32, IngressEvidence { observed_at: 100 });
/// let _duplicate = ingress.clone(); // no Clone impl — does not compile
/// ```
///
/// There is no accessor that returns just the stream or just the evidence
/// — both fields are private:
///
/// ```compile_fail
/// use mesh_session_core_rs::ingress::{PrevalidatedIngress, IngressEvidence};
/// let ingress = PrevalidatedIngress::new(42u32, IngressEvidence { observed_at: 100 });
/// let _just_the_stream: u32 = ingress.stream; // field is private
/// ```
///
/// And unlike the pre-hardening version, `consume` itself is not reachable
/// from outside this crate at all — the aggregate can be created (by an
/// adapter, a different crate) but not taken apart except internally:
///
/// ```compile_fail
/// use mesh_session_core_rs::ingress::{PrevalidatedIngress, IngressEvidence};
/// let ingress = PrevalidatedIngress::new(42u32, IngressEvidence { observed_at: 100 });
/// let _ = ingress.consume(); // pub(crate) — does not compile from outside the crate
/// ```
#[derive(Debug)]
pub struct PrevalidatedIngress<T> {
    stream: T,
    evidence: IngressEvidence,
}

impl<T> PrevalidatedIngress<T> {
    /// Only an adapter should call this — CORE itself never fabricates
    /// evidence for a stream it did not prefilter.
    pub fn new(stream: T, evidence: IngressEvidence) -> Self {
        Self { stream, evidence }
    }

    /// Consume `self` once, returning the stream and its evidence as an
    /// inseparable pair. `pub(crate)`: only this crate's own
    /// `start_session` may call this, and it does so internally, embedding
    /// the evidence in whatever session type it returns rather than
    /// handing either piece back out to its own caller. Taking `self` by
    /// value (not `&PrevalidatedIngress<T>`) also means a second call on
    /// the same binding is a use-after-move the compiler rejects outright.
    pub(crate) fn consume(self) -> (T, IngressEvidence) {
        (self.stream, self.evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consume_yields_the_same_stream_and_evidence_it_was_built_from() {
        let ingress = PrevalidatedIngress::new(42u32, IngressEvidence { observed_at: 100 });
        let (stream, evidence) = ingress.consume();
        assert_eq!(stream, 42);
        assert_eq!(evidence.observed_at, 100);
    }
}
