// Shared upstream suite sources are preserved in full; registration/configuration
// is adapted by the native harness. These object-entry suites are counted
// separately from the static *.test.ts source corpus.
import './adapter-suites/auth-flow.js';
import './adapter-suites/transactions.js';
import './adapter-suites/basic.js';
import './adapter-suites/joins.js';
