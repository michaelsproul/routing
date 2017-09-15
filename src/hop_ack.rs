use signature_accumulator::Signed;
use sha3;
use id::PublicId;
use std::collections::{BTreeMap, BTreeSet};
use rust_sodium::crypto::sign;
use std::mem;
use {QUORUM_NUMERATOR, QUORUM_DENOMINATOR};
use error::RoutingError;
use maidsafe_utilities::serialisation::serialise;
use tiny_keccak::sha3_256;
use messages::SignedMessage;

#[derive(Debug)]
pub struct HopAck {
    message_hash: sha3::Digest256,
    delegate_id: PublicId,
    /// Public IDs of the nodes that we expect to ACK this message.
    /// TODO: eventually replace by a data chain block ID.
    recipients: BTreeSet<PublicId>,
    signatures: BTreeMap<PublicId, sign::Signature>
}

impl HopAck {
    pub fn new(
        signed_message: &SignedMessage,
        delegate_id: PublicId,
        recipients: BTreeSet<PublicId>
    ) -> Result<Self, RoutingError>
    {
        let message_hash = sha3_256(&serialise(&signed_message.routing_message())?);
        Ok(HopAck {
            message_hash,
            delegate_id,
            recipients,
            signatures: BTreeMap::new(),
        })
    }

    fn remove_invalid_signatures(&mut self) -> Result<(), RoutingError> {
        let signed_data = serialise(&(self.message_hash, self.delegate_id))?;

        for (id, signature) in mem::replace(&mut self.signatures, BTreeMap::new()) {
            if sign::verify_detached(&signature, &signed_data, id.signing_public_key()) {
                let _ = self.signatures.insert(id, signature);
            }
        }
        Ok(())
    }
}

impl Signed for HopAck {
    /// Calculates the SHA3 digest of the object
    fn digest(&self) -> Option<sha3::Digest256> {
        Some(self.message_hash)
    }

    /// Checks whether the object has a quorum of signatures
    fn check_fully_signed(&mut self, _min_section_size: usize) -> bool {
        if let Err(_) = self.remove_invalid_signatures() {
            return false;
        }
        let signatories: BTreeSet<_> = self.signatures.keys().cloned().collect();
        let valid_signatories = (&signatories) & (&self.recipients);
        valid_signatories.len() * QUORUM_DENOMINATOR > self.recipients.len() * QUORUM_NUMERATOR
    }

    /// Adds the given signature if it is new, without validating it.
    fn add_signature(&mut self, pub_id: PublicId, sig: sign::Signature) {
        let _ = self.signatures.insert(pub_id, sig);
    }

    /// Adds all signatures from the given object, without validating them.
    fn add_signatures(&mut self, other: Self) {
        self.signatures.extend(other.signatures);
    }
}
