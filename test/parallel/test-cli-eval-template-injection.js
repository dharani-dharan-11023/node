'use strict';

// Test for security vulnerability CVE-XXXX-XXXX
// Template injection in --eval argument processing

const common = require('../common');
const assert = require('assert');
const child = require('child_process');

// Test that template injection attempts fail safely
// This should NOT execute arbitrary code when crypto wrapper is applied

// Test 1: Print mode template injection attempt
{
  const maliciousCode = '}; console.log("INJECTION_SUCCESS"); process.exit(42); void{ crypto';
  
  child.exec(
    ...common.escapePOSIXShell`"${process.execPath}" -e ${maliciousCode} -p`,
    common.mustCall((err, stdout, stderr) => {
      // Should result in syntax error, not code execution
      assert.ok(err, 'Should fail with syntax error');
      assert.notMatch(stdout, /INJECTION_SUCCESS/, 'Injection should not succeed');
      assert.notStrictEqual(err.code, 42, 'Should not execute injected exit code');
    }));
}

// Test 2: Non-print mode template injection attempt  
{
  const maliciousCode = '}; console.log("INJECTION_SUCCESS"); process.exit(43); {crypto';
  
  child.exec(
    ...common.escapePOSIXShell`"${process.execPath}" -e ${maliciousCode}`,
    common.mustCall((err, stdout, stderr) => {
      // Should result in syntax error, not code execution
      assert.ok(err, 'Should fail with syntax error');
      assert.notMatch(stdout, /INJECTION_SUCCESS/, 'Injection should not succeed');
      assert.notStrictEqual(err.code, 43, 'Should not execute injected exit code');
    }));
}

// Test 3: Verify crypto functionality still works normally
if (common.hasCrypto) {
  child.exec(
    ...common.escapePOSIXShell`"${process.execPath}" -e "console.log(typeof crypto.randomBytes)"`,
    common.mustSucceed((stdout, stderr) => {
      assert.strictEqual(stdout.trim(), 'function');
      assert.strictEqual(stderr, '');
    }));
}

// Test 4: Verify normal eval still works
{
  child.exec(
    ...common.escapePOSIXShell`"${process.execPath}" -e "console.log('normal eval works')"`,
    common.mustSucceed((stdout, stderr) => {
      assert.strictEqual(stdout, 'normal eval works\n');
      assert.strictEqual(stderr, '');
    }));
}