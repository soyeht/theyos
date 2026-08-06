use std::num::NonZeroUsize;
use std::time::Duration;

use household_rs::ids::HouseholdId;
use household_rs::mesh_intent_nonce_ledger::{
    MeshIntentNonceLedger, MeshIntentNonceLedgerConfig,
};

fn main() {
    let hh_id = HouseholdId::parse(format!("hh_{}", "a".repeat(52))).unwrap();
    let config = MeshIntentNonceLedgerConfig::new(
        NonZeroUsize::new(8).unwrap(),
        Duration::from_secs(1),
    )
    .unwrap();
    let _ = MeshIntentNonceLedger::open("/caller/chosen/state", hh_id, config);
}
