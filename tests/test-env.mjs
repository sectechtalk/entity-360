// Loaded before every test file (npm test runs node --import ./tests/test-env.mjs --test, and node --test passes
// --import on to each test process). Tests never read a real domain controller: on a Windows PC on the domain the test
// server would otherwise run live AD and AD posture reads (slow enough to break browser timings, and real LDAP
// traffic that Defender for Identity watches). Tests that cover the live path pass their own config.
process.env.E360_AD_ENABLED = 'false';
