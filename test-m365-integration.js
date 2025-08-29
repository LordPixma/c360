#!/usr/bin/env node
/**
 * Basic integration test for M365 OAuth endpoints
 * Tests endpoint structure and basic error handling without requiring real M365 credentials
 */

const BASE_URL = 'http://localhost:8787'; // Local dev server

async function testEndpoint(method, path, body = null, expectedStatus = 200) {
  try {
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json',
        'X-CSRF': 'test', // Required for POST endpoints
      },
    };
    
    if (body) {
      options.body = JSON.stringify(body);
    }
    
    const response = await fetch(`${BASE_URL}${path}`, options);
    const data = await response.json();
    
    console.log(`${method} ${path}`);
    console.log(`  Status: ${response.status} (expected: ${expectedStatus})`);
    console.log(`  Response:`, data);
    
    if (response.status === expectedStatus) {
      console.log(`  ✅ PASS\n`);
      return true;
    } else {
      console.log(`  ❌ FAIL\n`);
      return false;
    }
  } catch (error) {
    console.log(`${method} ${path}`);
    console.log(`  ❌ ERROR: ${error.message}\n`);
    return false;
  }
}

async function runTests() {
  console.log('🧪 Testing M365 OAuth Integration Endpoints\n');
  
  const tests = [
    // Test M365 authorize endpoint - should fail without env vars but with proper error
    () => testEndpoint('GET', '/auth/m365/authorize?tenant=test', null, 500),
    
    // Test M365 callback endpoint - should fail with invalid request
    () => testEndpoint('POST', '/auth/m365/callback', {}, 400),
    
    // Test M365 status endpoint - should work
    () => testEndpoint('GET', '/admin/m365/status?tenant=test', null, 404),
    
    // Test M365 configure endpoint - should fail with missing fields
    () => testEndpoint('POST', '/admin/m365/configure', {}, 400),
    
    // Test health endpoint - should always work
    () => testEndpoint('GET', '/health', null, 200),
  ];
  
  let passed = 0;
  let total = tests.length;
  
  for (const test of tests) {
    if (await test()) {
      passed++;
    }
  }
  
  console.log(`📊 Results: ${passed}/${total} tests passed`);
  
  if (passed === total) {
    console.log('🎉 All integration tests passed!');
    process.exit(0);
  } else {
    console.log('❌ Some tests failed');
    process.exit(1);
  }
}

// Only run if called directly
if (import.meta.url === `file://${process.argv[1]}`) {
  runTests().catch(console.error);
}

export { testEndpoint, runTests };