pragma circom 2.0.0;

// Poseidon2 S-box: x^5 transformation
template SBox() {
    signal input in;
    signal output out;
    
    signal x2 <== in * in;
    signal x4 <== x2 * x2;
    out <== x4 * in;
}

// Add round constants to state
template AddRoundConstants(t, round_constants, round) {
    signal input state[t];
    signal output out[t];
    
    for (var i = 0; i < t; i++) {
        out[i] <== state[i] + round_constants[round * t + i];
    }
}

// MDS matrix multiplication for Poseidon2 with t=3
template MixColumns() {
    signal input state[3];
    signal output out[3];
    
    // Optimized MDS matrix for t=3
    // This is a simplified version - in practice, you'd use specific MDS matrix values
    out[0] <== 2*state[0] + 3*state[1] + 1*state[2];
    out[1] <== 1*state[0] + 2*state[1] + 3*state[2];
    out[2] <== 3*state[0] + 1*state[1] + 2*state[2];
}

// Poseidon2 core permutation
template Poseidon2Core() {
    signal input initialState[3];
    signal output finalState[3];
    
    // Parameters for (n=256, t=3, d=5)
    var t = 3;
    var R_F = 8;  // Full rounds
    var R_P = 57; // Partial rounds
    var total_rounds = R_F + R_P;
    
    // Round constants (simplified - in practice these would be generated systematically)
    var round_constants[195] = [
        // First 4 full rounds
        123456789, 234567890, 345678901,
        456789012, 567890123, 678901234,
        789012345, 890123456, 901234567,
        111111111, 222222222, 333333333,
        
        // 57 partial rounds (only first element gets constant)
        444444444, 0, 0,
        555555555, 0, 0,
        666666666, 0, 0,
        777777777, 0, 0,
        888888888, 0, 0,
        999999999, 0, 0,
        101010101, 0, 0,
        121212121, 0, 0,
        131313131, 0, 0,
        141414141, 0, 0,
        151515151, 0, 0,
        161616161, 0, 0,
        171717171, 0, 0,
        181818181, 0, 0,
        191919191, 0, 0,
        202020202, 0, 0,
        212121212, 0, 0,
        222222223, 0, 0,
        232323232, 0, 0,
        242424242, 0, 0,
        252525252, 0, 0,
        262626262, 0, 0,
        272727272, 0, 0,
        282828282, 0, 0,
        292929292, 0, 0,
        303030303, 0, 0,
        313131313, 0, 0,
        323232323, 0, 0,
        333333334, 0, 0,
        343434343, 0, 0,
        353535353, 0, 0,
        363636363, 0, 0,
        373737373, 0, 0,
        383838383, 0, 0,
        393939393, 0, 0,
        404040404, 0, 0,
        414141414, 0, 0,
        424242424, 0, 0,
        434343434, 0, 0,
        444444445, 0, 0,
        454545454, 0, 0,
        464646464, 0, 0,
        474747474, 0, 0,
        484848484, 0, 0,
        494949494, 0, 0,
        505050505, 0, 0,
        515151515, 0, 0,
        525252525, 0, 0,
        535353535, 0, 0,
        545454545, 0, 0,
        555555556, 0, 0,
        565656565, 0, 0,
        575757575, 0, 0,
        585858585, 0, 0,
        595959595, 0, 0,
        606060606, 0, 0,
        
        // Last 4 full rounds
        616161616, 626262626, 636363636,
        646464646, 656565656, 666666667,
        676767676, 686868686, 696969696,
        707070707, 717171717, 727272727
    ];
    
    component sbox[total_rounds][t];
    component addRC[total_rounds];
    component mix[total_rounds];
    
    signal state[total_rounds + 1][t];
    
    // Initialize state
    for (var i = 0; i < t; i++) {
        state[0][i] <== initialState[i];
    }
    
    // Round function
    for (var round = 0; round < total_rounds; round++) {
        // Add round constants
        addRC[round] = AddRoundConstants(t, round_constants, round);
        for (var i = 0; i < t; i++) {
            addRC[round].state[i] <== state[round][i];
        }
        
        // Apply S-box
        if (round < R_F/2 || round >= R_F/2 + R_P) {
            // Full rounds: apply S-box to all elements
            for (var i = 0; i < t; i++) {
                sbox[round][i] = SBox();
                sbox[round][i].in <== addRC[round].out[i];
            }
        } else {
            // Partial rounds: apply S-box only to first element
            sbox[round][0] = SBox();
            sbox[round][0].in <== addRC[round].out[0];
            for (var i = 1; i < t; i++) {
                sbox[round][i] = SBox();
                sbox[round][i].in <== addRC[round].out[i];
                // In actual implementation, these would be identity, but circom requires components
            }
        }
        
        // Mix columns
        mix[round] = MixColumns();
        for (var i = 0; i < t; i++) {
            mix[round].state[i] <== sbox[round][i].out;
        }
        
        for (var i = 0; i < t; i++) {
            state[round + 1][i] <== mix[round].out[i];
        }
    }
    
    // Output final state
    for (var i = 0; i < t; i++) {
        finalState[i] <== state[total_rounds][i];
    }
}
