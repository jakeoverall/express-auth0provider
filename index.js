const AuthorizationService = require("./lib/Auth0Provider");
const MockAuth0Provider = require("./lib/MockAuth0Provider");

module.exports = {
  Auth0Provider: AuthorizationService.Auth0Provider,
  MockAuth0Provider: MockAuth0Provider.MockAuth0Provider,
};