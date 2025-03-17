use std::collections::BTreeMap;

use bincode::{Decode, Encode};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use sdk::{identity_provider::IdentityVerification, Digestable, RunResult};
use sha2::{Digest, Sha256};

/// Entry point of the contract's logic
pub fn execute(contract_input: sdk::ContractInput) -> RunResult<FarcasterIdentityContractState> {
    // Parse contract inputs
    let (input, action) =
        sdk::guest::init_raw::<sdk::identity_provider::IdentityAction>(contract_input);

    let action = action.ok_or("Failed to parse action")?;

    // Parse initial state
    let state: FarcasterIdentityContractState = input.initial_state.clone().into();

    // Extract private information (could be a signed message, public key, etc.)
    let private_input = core::str::from_utf8(&input.private_input).unwrap();

    // Execute the given action
    sdk::identity_provider::execute_action(state, action, private_input)
}

/// Struct to hold account's information for Farcaster identity
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone, Eq, PartialEq)]
pub struct FarcasterAccountInfo {
    pub fid: u64,                 // Farcaster ID
    pub public_key: String,       // Ed25519 public key in hex format
    pub nonce: u32,               // Replay protection nonce
    pub app_fid: Option<u64>,     // Application FID that created this signature (optional)
    pub username: Option<String>, // Farcaster username (optional)
}

/// The state of the contract, that is totally serialized on-chain
#[derive(Encode, Decode, Serialize, Deserialize, Debug, Clone)]
pub struct FarcasterIdentityContractState {
    identities: BTreeMap<String, FarcasterAccountInfo>,
}

/// Some helper methods for the state
impl FarcasterIdentityContractState {
    pub fn new() -> Self {
        FarcasterIdentityContractState {
            identities: BTreeMap::new(),
        }
    }

    pub fn get_nonce(&self, account: &str) -> Result<u32, &'static str> {
        let info = self.identities.get(account).ok_or("Identity not found")?;
        Ok(info.nonce)
    }
}

// The IdentityVerification trait implementation for Farcaster identity
impl IdentityVerification for FarcasterIdentityContractState {
    fn register_identity(
        &mut self,
        account: &str,
        private_input: &str,
    ) -> Result<(), &'static str> {
        // Parse the private input as JSON with FID, public key, etc.
        let account_data: serde_json::Value = serde_json::from_str(private_input)
            .map_err(|_| "Invalid Farcaster identity data")?;
        
        // Extract required fields
        let fid = account_data.get("fid")
            .and_then(|v| v.as_u64())
            .ok_or("Missing or invalid FID")?;
        
        let public_key = account_data.get("public_key")
            .and_then(|v| v.as_str())
            .ok_or("Missing or invalid public key")?
            .to_string();
        
        // Optional fields
        let app_fid = account_data.get("app_fid").and_then(|v| v.as_u64());
        let username = account_data.get("username").and_then(|v| v.as_str()).map(String::from);
        
        // Create account info
        let account_info = FarcasterAccountInfo {
            fid,
            public_key,
            nonce: 0,
            app_fid,
            username,
        };

        if self
            .identities
            .insert(account.to_string(), account_info)
            .is_some()
        {
            return Err("Identity already exists");
        }
        Ok(())
    }

    fn verify_identity(
        &mut self,
        account: &str,
        nonce: u32,
        private_input: &str,
    ) -> Result<bool, &'static str> {
        match self.identities.get_mut(account) {
            Some(stored_info) => {
                if nonce != stored_info.nonce {
                    return Err("Invalid nonce");
                }
                
                // Parse the private input which contains the signature and message
                let verify_data: serde_json::Value = serde_json::from_str(private_input)
                    .map_err(|_| "Invalid verification data")?;
                
                // Extract signature and message to verify
                let signature_hex = verify_data.get("signature")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing signature")?;
                
                let message = verify_data.get("message")
                    .and_then(|v| v.as_str())
                    .ok_or("Missing message")?;
                
                // Decode the public key from the stored info
                let public_key_bytes = hex::decode(&stored_info.public_key)
                    .map_err(|_| "Invalid stored public key")?;
                
                let verifying_key = VerifyingKey::from_bytes(
                    &public_key_bytes.try_into().map_err(|_| "Invalid public key length")?
                ).map_err(|_| "Invalid public key")?;
                
                // Decode the signature
                let signature_bytes = hex::decode(signature_hex)
                    .map_err(|_| "Invalid signature format")?;
                
                let signature = Signature::from_bytes(
                    &signature_bytes.try_into().map_err(|_| "Invalid signature length")?
                );
                
                // Verify the signature
                match verifying_key.verify(message.as_bytes(), &signature) {
                    Ok(_) => {
                        // Signature verification successful
                        stored_info.nonce += 1;
                        Ok(true)
                    },
                    Err(_) => Ok(false),
                }
            }
            None => Err("Identity not found"),
        }
    }

    fn get_identity_info(&self, account: &str) -> Result<String, &'static str> {
        match self.identities.get(account) {
            Some(info) => Ok(serde_json::to_string(&info).map_err(|_| "Failed to serialize")?),
            None => Err("Identity not found"),
        }
    }
}

impl Default for FarcasterIdentityContractState {
    fn default() -> Self {
        Self::new()
    }
}

/// Helpers to transform the contract's state into its on-chain state digest version.
impl Digestable for FarcasterIdentityContractState {
    fn as_digest(&self) -> sdk::StateDigest {
        sdk::StateDigest(
            bincode::encode_to_vec(self, bincode::config::standard())
                .expect("Failed to encode FarcasterIdentityContractState"),
        )
    }
}

impl From<sdk::StateDigest> for FarcasterIdentityContractState {
    fn from(state: sdk::StateDigest) -> Self {
        let (state, _) = bincode::decode_from_slice(&state.0, bincode::config::standard())
            .map_err(|_| "Could not decode Farcaster identity state".to_string())
            .unwrap();
        state
    }
}