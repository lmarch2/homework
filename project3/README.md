# Project 3: Poseidon2 Hash Function Circuit Implementation

## Overview

This project implements the Poseidon2 hash function as a zero-knowledge circuit using Circom, with parameters (n,t,d) = (256,3,5), and generates zero-knowledge proofs using the Groth16 proving system.

## Mathematical Background

### Poseidon2 Hash Function

Poseidon2 is an optimized version of the Poseidon hash function, designed specifically for zero-knowledge proof systems. It operates over a finite field and uses a substitution-permutation network (SPN) structure.

#### Algorithm Structure

The Poseidon2 permutation consists of the following steps:

1. **State Initialization**: The internal state is initialized with input values and padding
2. **Round Function**: Applied for a specific number of rounds, consisting of:
   - AddRoundKey (ARK): Adding round constants
   - SubBytes (S-box): Non-linear transformation using x^d (where d=5)
   - MixColumns: Linear transformation using MDS matrix

#### Parameters

For our implementation, we use the parameters (n=256, t=3, d=5):
- **n = 256**: Security level in bits
- **t = 3**: State size (number of field elements)
- **d = 5**: S-box degree (x^5)

#### Round Numbers

Based on the security analysis:
- **R_F = 8**: Number of full rounds
- **R_P = 57**: Number of partial rounds (for t=3)

#### Mathematical Formulation

Let F_p be a prime field where p is a large prime. The Poseidon2 permutation operates on a state of t field elements.

**State Update**:
For each round i, the state S is updated as:
1. **ARK**: S_i ← S_{i-1} + C_i (where C_i are round constants)
2. **S-box**: S_i[j] ← S_i[j]^5 for all j (full rounds) or j=0 (partial rounds)
3. **MixColumns**: S_i ← M × S_i (where M is the MDS matrix)

**Round Constants**: Generated using a secure method to ensure no algebraic structure that could be exploited.

**MDS Matrix**: Maximum Distance Separable matrix ensures optimal diffusion properties.

### Circuit Design

The circuit implements the following components:

1. **Input Handling**: Takes a single field element as private input (preimage)
2. **Padding**: Applies proper padding to create a t-element state
3. **Permutation**: Implements the full Poseidon2 permutation
4. **Output**: Produces the hash value as public output

#### Security Properties

- **Collision Resistance**: Computationally infeasible to find two inputs with the same hash
- **Preimage Resistance**: Given a hash, it's computationally infeasible to find the preimage
- **Second Preimage Resistance**: Given an input, it's computationally infeasible to find a different input with the same hash

## Implementation

### Circuit Structure

The main circuit `Poseidon2Hash` takes:
- **Private Input**: `preimage` - the value to be hashed
- **Public Output**: `hash` - the Poseidon2 hash of the preimage

### Components

1. **Poseidon2Core**: Implements the core permutation
2. **AddRoundKey**: Adds round constants to the state
3. **SBox**: Implements the x^5 S-box transformation
4. **MixColumns**: Applies the MDS matrix multiplication

## Zero-Knowledge Proof Generation

The project uses Groth16, a zk-SNARK proving system that provides:
- **Succinctness**: Proofs have constant size
- **Non-interactivity**: No interaction required between prover and verifier
- **Zero-knowledge**: Reveals nothing about the private input

### Proof Statement

The circuit proves: "I know a preimage x such that Poseidon2(x) = h" without revealing x.

## Testing and Verification

The implementation includes comprehensive tests to verify:
1. **Correctness**: Hash values match reference implementation
2. **Consistency**: Same input always produces same output  
3. **Proof Generation**: Groth16 proofs can be generated successfully
4. **Proof Verification**: Generated proofs verify correctly

## Performance Analysis

Circuit statistics and performance metrics are measured and reported, including:
- Number of constraints
- Proof generation time
- Verification time
- Memory usage

This implementation provides a foundation for privacy-preserving applications requiring cryptographic hash functions in zero-knowledge proofs.
