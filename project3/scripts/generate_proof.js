#!/usr/bin/env node

const snarkjs = require("snarkjs");
const fs = require("fs");
const path = require("path");

async function generateProof() {
    console.log("Generating Groth16 proof for Poseidon2 hash...");
    
    const buildDir = path.join(__dirname, "..", "build");
    
    // Ensure build directory exists
    if (!fs.existsSync(buildDir)) {
        fs.mkdirSync(buildDir, { recursive: true });
    }
    
    // Input for the proof
    const input = {
        preimage: 42  // Secret input
    };
    
    const inputPath = path.join(buildDir, "input.json");
    fs.writeFileSync(inputPath, JSON.stringify(input, null, 2));
    
    console.log("Input saved to:", inputPath);
    console.log("Input:", input);
    
    console.log("\nTo complete the proof generation, run these commands:");
    console.log("\n1. Compile the circuit:");
    console.log(`   cd ${path.join(__dirname, "..")}`);
    console.log("   circom circuits/poseidon2_hash.circom --r1cs --wasm --sym -o build/");
    
    console.log("\n2. Download powers of tau:");
    console.log("   wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau -O build/powersOfTau28_hez_final_12.ptau");
    
    console.log("\n3. Generate proving key:");
    console.log("   snarkjs groth16 setup build/poseidon2_hash.r1cs build/powersOfTau28_hez_final_12.ptau build/poseidon2_hash_0000.zkey");
    
    console.log("\n4. Generate final zkey (optional ceremony):");
    console.log("   snarkjs zkey contribute build/poseidon2_hash_0000.zkey build/poseidon2_hash_final.zkey --name='First contribution' -v");
    
    console.log("\n5. Export verification key:");
    console.log("   snarkjs zkey export verificationkey build/poseidon2_hash_final.zkey build/verification_key.json");
    
    console.log("\n6. Generate witness:");
    console.log("   node build/poseidon2_hash_js/generate_witness.js build/poseidon2_hash_js/poseidon2_hash.wasm build/input.json build/witness.wtns");
    
    console.log("\n7. Generate proof:");
    console.log("   snarkjs groth16 prove build/poseidon2_hash_final.zkey build/witness.wtns build/proof.json build/public.json");
    
    console.log("\n8. Verify proof:");
    console.log("   snarkjs groth16 verify build/verification_key.json build/public.json build/proof.json");
}

// Run the demo
if (require.main === module) {
    generateProof().catch(console.error);
}

module.exports = { generateProof };
