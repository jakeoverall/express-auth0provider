const https = require("https");
const { BadRequest } = require("./Errors.js");
function httpRequest(url, options) {
  return new Promise((resolve, reject) => {
    https.get(url, options, (res) => {
      let data = "";
      res.on("data", (chunk) => {
        data += chunk;
      });
      res.on("end", () => {
        try {
          resolve(JSON.parse(data));
        } catch (error) {
          reject(new BadRequest('Malformed or Expired Token'));
        }
      });
    }).on("error", (err) => {
      reject(err);
    });
  });
}

exports.httpRequest = httpRequest;