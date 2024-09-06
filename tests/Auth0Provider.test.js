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

    test('Fails on invalid roles', () => {
      // Test when user does not have valid roles
      const req = { userInfo: { roles: ['role1', 'role2'] } };
      const next = jest.fn();
      const middleware = Auth0Provider.hasRoles('role3');
      middleware(req, null, next);

      next.mockImplementation((error) => {
        expect(error).toBeInstanceOf(Forbidden);
      })
    })

    test('Middleware can be called without isAuthorized', () => {

      const req = get_valid_req();
      const next = jest.fn();
      const middleware = Auth0Provider.hasRoles('anything');
      middleware(req, null, next);

      next.mockImplementation(() => {
        expect(req.userInfo).toBeDefined();
      })

    })

  });

  describe('hasPermissions method', () => {
    test('should call next for valid permissions', () => {
      // Test when user has valid permissions
      const req = { userInfo: { permissions: ['perm1', 'perm2'] } };
      const next = jest.fn();
      const middleware = Auth0Provider.hasPermissions('perm1');

      middleware(req, null, next);

      expect(next).toHaveBeenCalled();
    });

    test('Fails on invalid permissions', () => {
      // Test when user does not have valid roles
      const req = { userInfo: { permissions: ['read:rules'] } };
      const next = jest.fn();
      const middleware = Auth0Provider.hasRoles('write:rules');
      middleware(req, null, next);

      next.mockImplementation((error) => {
        expect(error).toBeInstanceOf(Forbidden);
      })
    })

    test('Middleware can be called without isAuthorized', () => {

      const req = get_valid_req();
      const next = jest.fn();
      const middleware = Auth0Provider.hasPermissions('do:anything');
      middleware(req, null, next);

      next.mockImplementation(() => {
        expect(req.userInfo).toBeDefined();
      })

    })

  });

  describe('getAuthorizedUserInfo method', () => {
    test('should call getUserInfoFromBearerToken for authorized user', async () => {
      // Test when user is authorized
      const next = jest.fn();
      const req = get_valid_req()
      Auth0Provider.getAuthorizedUserInfo(req, null, next);
      next.mockImplementation(() => {
        expect(req.userInfo).toBeDefined()
      });
    });

  });

  describe('stripUrlBasedClaims method', () => {
    test('should bring scoped properties to top-level props', async () => {
      const expectedPermissions = ['access:admin', 'manage:user', 'read:data'];
      const expectedIds = ['auth-id', 'another-id'];
      const userInfo = {
        sub: "auth0|1234567890",
        nickname: "test",
        name: "test@testdomain.com",
        picture: "https://s.gravatar.com/avatar/test.png",
        email: "test@testdomain.com",
        email_verified: false,
        "https://auth.domain.com/id": "auth-id",
        "https://another-url.com/id": "another-id",
        "https://auth.domain.com/permissions": [
          "access:admin",
          "read:data"
        ],
        "https://another-url.com/permissions": [
          "manage:user",
          "read:data"
        ]
      }

      const data = Auth0Provider.stripUrlBasedClaims(userInfo);

      // Ensure the top-level permissions array contains the merged permissions from all scoped properties
      expect(data.permissions).toEqual(expect.arrayContaining(expectedPermissions));

      // Ensure the top-level ids array contains the ids from all scoped properties
      expect(data.ids).toEqual(expect.arrayContaining(expectedIds));

    });

    test('Top level id is single value if only one scoped id is present', async () => {
      const expectedIds = ['auth-id'];
      const userInfo = {
        sub: "auth0|1234567890",
        nickname: "test",
        name: "",
        picture: "https://s.gravatar.com/avatar/test.png",
        email: "",
        email_verified: false,
        "https://auth.domain.com/id": "auth-id",
        "https://auth.domain.com/permissions": [
          "access:admin",
          "read:data"
        ]
      }

      const data = Auth0Provider.stripUrlBasedClaims(userInfo);

      // Ensure the top-level id is a single value
      expect(data.id).toEqual(expectedIds[0]);

    });
  });
});


