const fs = require('fs');
const configPath = __dirname + '/config.dev.json';

// @ts-ignore
const config = JSON.parse(fs.readFileSync(configPath));


jest.mock("https", () => ({
  get: jest.fn((url, options, callback) => {
    const res = {
      on: jest.fn((event, handler) => {
        if (event === "data") handler(JSON.stringify({ success: true }));
        if (event === "end") handler();
      }),
      statusCode: 200,
    };
    callback(res);
    return { on: jest.fn(), end: jest.fn() }; // Ensure the request is properly closed
  }),
}));



// Assign config and token to global variables accessible in tests
global.testConfig = config;

