const fs = require('fs');
const configPath = __dirname + '/config.dev.json';
const tokenPath = __dirname + '/bearerToken.txt';

// @ts-ignore
const config = JSON.parse(fs.readFileSync(configPath));
const bearerToken = fs.readFileSync(tokenPath, 'utf8').trim();

// Assign config and token to global variables accessible in tests
global.testConfig = config;
global.testBearerToken = bearerToken;

