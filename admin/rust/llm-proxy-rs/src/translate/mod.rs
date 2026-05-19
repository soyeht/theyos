//! Pure shape-translation between OpenAI's `/v1/chat/completions` schema
//! and other providers' native schemas.
//!
//! Each upstream's translation lives in its own submodule so it can be
//! tested in isolation. The provider implementations (`provider::*`) wrap
//! these with the actual HTTP plumbing.

pub mod anthropic;
