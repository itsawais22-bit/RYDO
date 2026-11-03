'use strict';
// Creates db/rydo.db and all tables (safe to run repeatedly).
const config = require('../src/config');
require('../src/db');
console.log(`Database ready at ${config.dbPath}`);
