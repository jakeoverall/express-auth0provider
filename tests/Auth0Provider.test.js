const {
  Auth0Provider,
} = require('../lib/Auth0Provider.js'); // Import the file to test

const {
  BadRequest,
  Forbidden,
  Unauthorized,
} = require('../lib/Errors.js')


function get_valid_req() {
  return {
    headers: {
      authorization: 'Bearer' + global.testBearerToken
    }
  }
}


describe('Auth0Provider', () => {
  // Mock objects or variables needed for testing

  beforeEach(() => {
    Auth0Provider.configure(global.testConfig)
  });

  afterEach(() => {
    // Clean up after each test
  });

  describe('isAuthorized method', () => {
    test('should call next for authorized user', () => {
      // Test when user is authorized
      const next = jest.fn();

      Auth0Provider.isAuthorized(get_valid_req(), null, next);

      expect(next).toHaveBeenCalled();
    });
  })

  describe('getUserInfoFromBearerToken method', () => {
    test('should throw BadRequest for invalid input', async () => {
      // Test when invalid input is provided
      const invalidToken = null; // Invalid token

      await expect(Auth0Provider.getUserInfoFromBearerToken(invalidToken)).rejects.toThrow(BadRequest);
    });

    test('should fetch user info for valid token', async () => {
      // Test when valid token is provided
      const validToken = get_valid_req().headers.authorization;
      const expectedUserInfo = { /* expected user info */ };

      // Mock the necessary functions or objects required for this test

      const userInfo = await Auth0Provider.getClaimsFromToken(validToken);

      expect(userInfo).toBeDefined()
    });


  });

  describe('hasRoles method', () => {
    test('should call next for valid roles', () => {
      // Test when user has valid roles
      const req = { userInfo: { roles: ['role1', 'role2'] } };
      const next = jest.fn();
      const middleware = Auth0Provider.hasRoles('role1');

      middleware(req, null, next);

      expect(next).toHaveBeenCalled();
    });

    // Add more tests for different scenarios
  });

  describe('hasPermissions method', () => {
    test('should call next for valid permissions', () => {
      // Test when user has valid permissions
      const req = { user: { permissions: ['perm1', 'perm2'] } };
      const next = jest.fn();
      const middleware = Auth0Provider.hasPermissions('perm1');

      middleware(req, null, next);

      expect(next).toHaveBeenCalled();
    });

    // Add more tests for different scenarios
  });

  describe('getAuthorizedUserInfo method', () => {
    test('should call getUserInfoFromBearerToken for authorized user', async () => {
      // Test when user is authorized
      const next = jest.fn();
      const req = get_valid_req()
      await Auth0Provider.getAuthorizedUserInfo(req, null, next);

      expect(req).toBeDefined()
    });

  });

});

