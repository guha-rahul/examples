# Farcaster Identity Contract for Hylé

This project implements a zero-knowledge proof identity verification system using Farcaster IDs, integrated with the Hylé blockchain.

## Overview

The Farcaster Identity Contract allows applications on the Hylé network to verify user identities through Farcaster's authentication system. This enables:

- Securely verifying that a user controls a specific Farcaster ID (FID)
- Creating verifiable links between blockchain addresses and Farcaster identities
- Implementing permissioned operations that require Farcaster identity verification

## Architecture

This implementation consists of:

1. **Contract**: Core logic for registering and verifying Farcaster identities
2. **Guest**: RISC-0 ZK-proof guest code that executes the contract logic
3. **Host**: Client application that interacts with the contract and Farcaster APIs

## Features

- **Ed25519 Key Pairs**: Uses the same cryptographic primitives as Farcaster for compatibility
- **Farcaster Integration**: Simulates Farcaster's signed key request flow
- **ZK-Proofs**: Identity verification occurs through zero-knowledge proofs
- **CLI Interface**: Easy-to-use commands for managing Farcaster identities

## Usage

### Setup

```bash
# Clone the repository
git clone https://github.com/your-org/farcaster-identity
cd farcaster-identity

# Build the project
cargo build
```

### Register the Contract

```bash
cargo run -- register-contract
```

### Generate an Ed25519 Key Pair

```bash
cargo run -- generate-key-pair --output-file my_keys.json
```

### Simulate Farcaster Signer QR Code

```bash
cargo run -- get-signer-qr-code --app-fid 12345
```

### Register a Farcaster Identity

```bash
cargo run -- register-identity 0x123abc 42069 --app-fid 12345 --username "alice"
```

### Verify a Farcaster Identity

```bash
cargo run -- verify-identity 0x123abc 0 "Hello Hylé from Farcaster!"
```

## How It Works

1. **Identity Registration**:
   - Generate an Ed25519 key pair compatible with Farcaster
   - Store the public key in the contract state, associated with a Farcaster ID
   - Keep the private key secure for signing messages

2. **Identity Verification**:
   - Sign a message using the Ed25519 private key associated with a Farcaster ID
   - Submit the message and signature to the contract for verification
   - The contract verifies the signature matches the stored public key

3. **Farcaster Integration**:
   - Generate QR codes for Farcaster signer registration
   - Support the Farcaster signed key request flow
   - Link application FIDs with user FIDs

## Development Mode

This implementation uses RISC-0 in development mode for faster testing. For production use, enable full proof generation.

## License

This project is licensed under the same terms as the Hylé project.