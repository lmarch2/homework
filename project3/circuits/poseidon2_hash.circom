pragma circom 2.0.0;

include "poseidon2_core.circom";

// Main Poseidon2 hash circuit
template Poseidon2Hash() {
    // Private input: the preimage to be hashed
    signal input preimage;
    
    // Public output: the hash value
    signal output hash;
    
    // Initialize state with input and padding
    // For single input, we use: [preimage, 0, capacity]
    // where capacity is a domain separator
    component core = Poseidon2Core();
    core.initialState[0] <== preimage;
    core.initialState[1] <== 0;  // Padding
    core.initialState[2] <== 1;  // Domain separator/capacity
    
    // The hash is the first element of the final state
    hash <== core.finalState[0];
}

// Main component for the circuit
component main = Poseidon2Hash();
