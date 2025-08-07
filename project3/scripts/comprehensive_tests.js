#!/usr/bin/env node

const fs = require("fs");
const path = require("path");
const { execSync } = require("child_process");

async function runComprehensiveTests() {
    console.log("=".repeat(60));
    console.log("    Poseidon2 综合测试套件");
    console.log("=".repeat(60));
    console.log();

    const testCases = [
        { preimage: 0, description: "零值测试" },
        { preimage: 1, description: "单位值测试" },
        { preimage: 42, description: "已验证案例" },
        { preimage: 123456789, description: "大数值测试" },
        { preimage: 999999999, description: "边界值测试" }
    ];

    const results = [];

    for (let i = 0; i < testCases.length; i++) {
        const testCase = testCases[i];
        console.log(`测试案例 ${i + 1}: ${testCase.description}`);
        console.log(`输入: ${testCase.preimage}`);
        
        try {
            // 创建输入文件
            const inputFile = `build/test_input_${i}.json`;
            fs.writeFileSync(inputFile, JSON.stringify({ preimage: testCase.preimage }, null, 2));
            
            // 生成见证
            const witnessFile = `build/test_witness_${i}.wtns`;
            execSync(`node build/poseidon2_hash_js/generate_witness.js build/poseidon2_hash_js/poseidon2_hash.wasm ${inputFile} ${witnessFile}`, 
                { stdio: 'inherit' });
            
            // 生成证明
            const proofFile = `build/test_proof_${i}.json`;
            const publicFile = `build/test_public_${i}.json`;
            execSync(`node node_modules/snarkjs/build/cli.cjs groth16 prove build/poseidon2_hash_final.zkey ${witnessFile} ${proofFile} ${publicFile}`, 
                { stdio: 'pipe' });
            
            // 验证证明
            const verifyResult = execSync(`node node_modules/snarkjs/build/cli.cjs groth16 verify build/verification_key.json ${publicFile} ${proofFile}`, 
                { encoding: 'utf8' });
            
            const publicOutput = JSON.parse(fs.readFileSync(publicFile, 'utf8'));
            const hash = publicOutput[0];
            
            const success = verifyResult.includes("OK!");
            
            console.log(`哈希输出: ${hash}`);
            console.log(`证明验证: ${success ? '通过 ✓' : '失败 ✗'}`);
            console.log();
            
            results.push({
                testCase: i + 1,
                description: testCase.description,
                input: testCase.preimage,
                hash: hash,
                verification: success
            });
            
        } catch (error) {
            console.log(`证明验证: 失败 ✗`);
            console.log(`错误: ${error.message}`);
            console.log();
            
            results.push({
                testCase: i + 1,
                description: testCase.description,
                input: testCase.preimage,
                error: error.message,
                verification: false
            });
        }
    }

    // 生成测试总结
    console.log("=".repeat(60));
    console.log("    测试总结");
    console.log("=".repeat(60));
    
    const passedTests = results.filter(r => r.verification).length;
    const totalTests = results.length;
    
    console.log(`总测试数: ${totalTests}`);
    console.log(`通过测试: ${passedTests}`);
    console.log(`失败测试: ${totalTests - passedTests}`);
    console.log(`成功率: ${(passedTests/totalTests*100).toFixed(1)}%`);
    console.log();
    
    // 验证哈希唯一性
    const hashes = results.filter(r => r.hash).map(r => r.hash);
    const uniqueHashes = [...new Set(hashes)];
    
    console.log("哈希唯一性验证:");
    console.log(`生成的哈希数: ${hashes.length}`);
    console.log(`唯一哈希数: ${uniqueHashes.length}`);
    console.log(`唯一性检查: ${hashes.length === uniqueHashes.length ? '通过 ✓' : '失败 ✗'}`);
    console.log();
    
    // 保存测试结果
    const testReport = {
        timestamp: new Date().toISOString(),
        summary: {
            total_tests: totalTests,
            passed_tests: passedTests,
            failed_tests: totalTests - passedTests,
            success_rate: (passedTests/totalTests*100).toFixed(1) + "%"
        },
        hash_uniqueness: {
            total_hashes: hashes.length,
            unique_hashes: uniqueHashes.length,
            uniqueness_check: hashes.length === uniqueHashes.length
        },
        test_results: results
    };
    
    fs.writeFileSync('build/comprehensive_test_report.json', JSON.stringify(testReport, null, 2));
    
    console.log("详细测试报告已保存至: build/comprehensive_test_report.json");
    console.log("=".repeat(60));
}

if (require.main === module) {
    runComprehensiveTests().catch(console.error);
}

module.exports = { runComprehensiveTests };
