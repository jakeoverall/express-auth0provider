const fs = require('fs');
const configPath = __dirname + '/config.dev.json';

// @ts-ignore
const config = JSON.parse(fs.readFileSync(configPath));

// Assign config and token to global variables accessible in tests
global.testConfig = config;

