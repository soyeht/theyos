//! `PrevalidatedIngress<T>` scaffolding (Fila 1 item 5, CFX-1/RED-42).
//!
//! B-SESSAO v6 §2: the v4 bug was `authorize_mesh_peer(ingress, session,
//! ...)` accepting a *separate* ingress parameter alongside a session that
//! already embedded one — evidence from stream A could be paired with
//! stream B. The fix is an aggregate the adapter builds once, that a
//! constructor consumes by move and never re-exposes in pieces.
//!
//! **Scope note:** this module provides the ingress-side half of that
//! guard — the type cannot be cloned, and there is no method that returns
//! `T` or `IngressEvidence` alone, only both together via [`PrevalidatedIngress::consume`].
//! The session-side half of RED-42 (no `authorize(session, ingress)`
//! function once a session exists) requires `VerifiedMeshSession`/
//! `start_session`/`authorize_mesh_peer`, none of which are implemented
//! here — those belong to the state-machine track (out of Fila 1 item 5's
//! scope; the queue doc is explicit the type does not need an adapter or a
//! session to exist). Do not read this module alone as a closed RED-42.

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
/// builds this: no `Clone`, no accessor that returns one without the
/// other, and the only way to get either out is [`consume`](Self::consume),
/// which takes `self` by value and yields both at once.
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
/// — both fields are private, only [`consume`](Self::consume) reaches them,
/// and only as a pair:
///
/// ```compile_fail
/// use mesh_session_core_rs::ingress::{PrevalidatedIngress, IngressEvidence};
/// let ingress = PrevalidatedIngress::new(42u32, IngressEvidence { observed_at: 100 });
/// let _just_the_stream: u32 = ingress.stream; // field is private
/// ```
///
/// Using `ingress` again after [`consume`](Self::consume) (which takes
/// `self` by value) is a use-after-move the compiler rejects outright —
/// exactly the "cannot re-pair evidence with a different stream via the
/// original handle" property this type exists for:
///
/// ```compile_fail
/// use mesh_session_core_rs::ingress::{PrevalidatedIngress, IngressEvidence};
/// let ingress = PrevalidatedIngress::new(42u32, IngressEvidence { observed_at: 100 });
/// let _ = ingress.consume();
/// let _ = ingress.consume(); // use after move — does not compile
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
    /// inseparable pair. A future `start_session` must take
    /// `PrevalidatedIngress<T>` by value (as this method does) for the
    /// same reason — a `&PrevalidatedIngress<T>` parameter would let a
    /// caller retain and reuse the ingress after "consuming" it, which is
    /// exactly the aliasing v4's bug allowed.
    pub fn consume(self) -> (T, IngressEvidence) {
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
