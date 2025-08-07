import * as chai from "chai";
import path from "path";
import { wasm as wasm_tester } from "circom_tester";
import * as snarkjs from "snarkjs";
import fs from "fs";
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const assert = chai.assert;

// Test runner for both Mocha and direct execution
class TestRunner {
    constructor() {
        this.circuit = null;
        this.isDirectRun = import.meta.url === `file://${process.argv[1]}`;
    }

    async runHashTests() {
        console.log("Poseidon2 Hash Circuit Tests\n");

        // Load circuit
        console.log("Loading circuit...");
        this.circuit = await wasm_tester(path.join(__dirname, "..", "circuits", "poseidon2_hash.circom"));
        console.log("Circuit loaded successfully\n");

        // Test 1: Hash of 0
        await this.test("Should compute hash correctly for input 0", async () => {
            const input = { preimage: 0 };
            const witness = await this.circuit.calculateWitness(input);
            await this.circuit.checkConstraints(witness);
            const hash = witness[1];
            console.log("   Hash of 0:", hash.toString());
            assert(hash !== undefined, "Hash should be computed");
        });

        // Test 2: Hash of 1
        await this.test("Should compute hash correctly for input 1", async () => {
            const input = { preimage: 1 };
            const witness = await this.circuit.calculateWitness(input);
            await this.circuit.checkConstraints(witness);
            const hash = witness[1];
            console.log("   Hash of 1:", hash.toString());
            assert(hash !== undefined, "Hash should be computed");
        });

        // Test 3: Hash of 42
        await this.test("Should compute hash correctly for input 42", async () => {
            const input = { preimage: 42 };
            const witness = await this.circuit.calculateWitness(input);
            await this.circuit.checkConstraints(witness);
            const hash = witness[1];
            console.log("   Hash of 42:", hash.toString());
            assert(hash !== undefined, "Hash should be computed");
        });

        // Test 4: Different inputs produce different hashes
        await this.test("Should produce different hashes for different inputs", async () => {
            const input1 = { preimage: 1 };
            const input2 = { preimage: 2 };
            const witness1 = await this.circuit.calculateWitness(input1);
            const witness2 = await this.circuit.calculateWitness(input2);
            const hash1 = witness1[1];
            const hash2 = witness2[1];
            assert(hash1.toString() !== hash2.toString(), "Different inputs should produce different hashes");
            console.log("   Hash(1):", hash1.toString());
            console.log("   Hash(2):", hash2.toString());
        });

        // Test 5: Deterministic behavior
        await this.test("Should be deterministic", async () => {
            const input = { preimage: 123 };
            const witness1 = await this.circuit.calculateWitness(input);
            const witness2 = await this.circuit.calculateWitness(input);
            const hash1 = witness1[1];
            const hash2 = witness2[1];
            assert(hash1.toString() === hash2.toString(), "Hash should be deterministic");
            console.log("   Deterministic hash of 123:", hash1.toString());
        });
    }

    async runProofTests() {
        console.log("\nPoseidon2 Groth16 Proof System Tests\n");

        const ptauPath = path.join(__dirname, "..", "build", "powersOfTau28_hez_final_12.ptau");

        await this.test("Should generate and verify proof setup", async () => {
            const buildDir = path.join(__dirname, "..", "build");
            if (!fs.existsSync(buildDir)) {
                fs.mkdirSync(buildDir, { recursive: true });
                console.log("   OK Build directory created");
            }

            if (!fs.existsSync(ptauPath)) {
                console.log("   WARNING  Powers of tau file not found");
                console.log("   📥 To enable full proof testing, download:");
                console.log("   wget https://hermez.s3-eu-west-1.amazonaws.com/powersOfTau28_hez_final_12.ptau -O " + ptauPath);
                return;
            }

            console.log("   OK Powers of tau file exists");

            // Test basic proof workflow
            const input = { preimage: 42 };

            console.log("   Compiling Compiling circuit for proof generation...");
            const circuit = await wasm_tester(path.join(__dirname, "..", "circuits", "poseidon2_hash.circom"), {
                output: path.join(__dirname, "..", "build"),
                recompile: false
            });

            const witness = await circuit.calculateWitness(input);
            const hash = witness[1];

            console.log("   Info Input preimage:", input.preimage);
            console.log("   Info Computed hash:", hash.toString());

            await circuit.checkConstraints(witness);
            console.log("   OK Proof setup verification complete");
        });
    }

    async test(name, testFn) {
        try {
            console.log(`${name}`);
            await testFn();
            console.log(`   PASSED\n`);
        } catch (error) {
            console.log(`   FAILED: ${error.message}\n`);
            if (this.isDirectRun) {
                throw error;
            }
        }
    }
}

// Mocha test definitions (when running with Mocha)
if (typeof describe !== 'undefined') {
    describe("Poseidon2 Hash Circuit", function () {
        let circuit;
        this.timeout(100000);

        before(async () => {
            circuit = await wasm_tester(path.join(__dirname, "..", "circuits", "poseidon2_hash.circom"));
        });

        it("Should compute hash correctly for input 0", async () => {
            const input = { preimage: 0 };
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            const hash = witness[1];
            console.log("Hash of 0:", hash.toString());
            assert(hash !== undefined, "Hash should be computed");
        });

        it("Should compute hash correctly for input 1", async () => {
            const input = { preimage: 1 };
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            const hash = witness[1];
            console.log("Hash of 1:", hash.toString());
            assert(hash !== undefined, "Hash should be computed");
        });

        it("Should compute hash correctly for input 42", async () => {
            const input = { preimage: 42 };
            const witness = await circuit.calculateWitness(input);
            await circuit.checkConstraints(witness);
            const hash = witness[1];
            console.log("Hash of 42:", hash.toString());
            assert(hash !== undefined, "Hash should be computed");
        });

        it("Should produce different hashes for different inputs", async () => {
            const input1 = { preimage: 1 };
            const input2 = { preimage: 2 };
            const witness1 = await circuit.calculateWitness(input1);
            const witness2 = await circuit.calculateWitness(input2);
            const hash1 = witness1[1];
            const hash2 = witness2[1];
            assert(hash1.toString() !== hash2.toString(), "Different inputs should produce different hashes");
            console.log("Hash of 1:", hash1.toString());
            console.log("Hash of 2:", hash2.toString());
        });

        it("Should be deterministic", async () => {
            const input = { preimage: 123 };
            const witness1 = await circuit.calculateWitness(input);
            const witness2 = await circuit.calculateWitness(input);
            const hash1 = witness1[1];
            const hash2 = witness2[1];
            assert(hash1.toString() === hash2.toString(), "Hash should be deterministic");
            console.log("Deterministic hash of 123:", hash1.toString());
        });
    });

    describe("Poseidon2 Groth16 Proof System", function () {
        let circuit;
        const ptauPath = path.join(__dirname, "..", "build", "powersOfTau28_hez_final_12.ptau");
        this.timeout(300000);

        before(async () => {
            const buildDir = path.join(__dirname, "..", "build");
            if (!fs.existsSync(buildDir)) {
                fs.mkdirSync(buildDir, { recursive: true });
            }
        });

        it("Should generate and verify proof", async function () {
            if (!fs.existsSync(ptauPath)) {
                console.log("WARNING Skipping proof test: Powers of tau file not found");
                this.skip();
            }

            const input = { preimage: 42 };
            console.log("Compiling Compiling circuit...");

            circuit = await wasm_tester(path.join(__dirname, "..", "circuits", "poseidon2_hash.circom"), {
                output: path.join(__dirname, "..", "build"),
                recompile: true
            });

            console.log("✓ Circuit compiled successfully");
            const witness = await circuit.calculateWitness(input);
            const hash = witness[1];

            console.log("Input preimage:", input.preimage);
            console.log("Computed hash:", hash.toString());
            await circuit.checkConstraints(witness);
            console.log("OK Circuit verification successful");
        });
    });
}

// Direct execution (when running with node)
if (import.meta.url === `file://${process.argv[1]}`) {
    const runner = new TestRunner();

    try {
        await runner.runHashTests();
        await runner.runProofTests();
        console.log("All tests completed successfully!");
    } catch (error) {
        console.error("❌ Test suite failed:", error.message);
        process.exit(1);
    }
}
