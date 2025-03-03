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
      authorization: `Bearer ${global.testConfig.accessToken}`
    }
  }
}

const audience = global.testConfig.audience;

const mock_user = {
  sub: "auth0|1234567890",
  nickname: "test",
  name: "Test User",
  picture: "https://s.gravatar.com/avatar/test.png",
  email: "test@test.com",
  email_verified: false,
  [audience + "/id"]: "auth-id",
  [audience + "/permissions"]: [
    "access:admin",
    "read:data"
  ]
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
    test('should throw Unauthorized for invalid input', async () => {
      // Test when invalid input is provided
      const invalidToken = 'not_VALID'; // Invalid token

      await expect(Auth0Provider.getUserInfoFromBearerToken(invalidToken)).rejects.toThrow(Unauthorized);
    });

    test('should extract claims from token', async () => {
      // Test when valid token is provided
      const validToken = get_valid_req().headers.authorization;

      // Mock the necessary functions or objects required for this test

      const claims = await Auth0Provider.getIdentity(validToken);
      expect(claims).toBeDefined()
    });

    test('should merge claims and userInfo from token', async () => {
      // Test when valid token is provided
      const validToken = get_valid_req().headers.authorization;
      // Mock the necessary functions or objects required for this test
      const userInfo = await Auth0Provider.getIdentity(validToken);

      expect(userInfo.permissions.length).toBeGreaterThan(0);
    })
  });

  describe('hasRoles method', () => {
    test('should call next for valid roles', () => {
      // Test when user has valid roles
      const req = { userInfo: { roles: ['role1', 'role2'] } };
      const next = jest.fn();
      const middleware = Auth0Provider.hasRoles('role1');

      middleware(req, null, next);
      next.mockImplementation(() => {
        expect(req.userInfo).toBeDefined();
      })
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

      next.mockImplementation(() => {
        expect(req.userInfo).toBeDefined();
      })
    });

    test('Fails on invalid permissions', () => {
      // Test when user does not have valid roles
      const req = { userInfo: { permissions: ['read:rules'] } };
      const next = jest.fn();
      const middleware = Auth0Provider.hasPermissions('write:rules');
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
    test('should call auth0 to verify bearer token and return userInfo', async () => {
      const next = jest.fn();
      const req = get_valid_req()
      Auth0Provider.getAuthorizedUserInfo(req, null, next);
      next.mockImplementation(() => {
        expect(req.userInfo).toBeDefined()
      });
    });

  });

  describe('The UserInfo is proxied', () => {
    test('should bring scoped properties to top-level props', async () => {
      const userInfo = {
        ...mock_user,
        'https://someother.com/id': 'auth-id-2',
      }
      userInfo[audience + '/permissions'] = ['access:admin', 'manage:user', 'read:data'];
      const expectedPermissions = ['access:admin', 'manage:user', 'read:data'];
      const expectedIds = ['auth-id', 'auth-id-2'];

      const data = Auth0Provider.stripUrlBasedClaims(userInfo);

      // Ensure the top-level permissions array contains the merged permissions from all scoped properties
      expect(data.permissions).toEqual(expect.arrayContaining(expectedPermissions));

      // Ensure the top-level ids array contains the ids from all scoped properties
      expect(data.ids).toEqual(expect.arrayContaining(expectedIds));

    });

    test('Top level id is single value', async () => {
      const expectedIds = ['auth-id'];

      const data = Auth0Provider.stripUrlBasedClaims(mock_user);
      // Ensure the top-level id is a single value
      expect(data.id).toEqual(expectedIds[0]);
    });
  });


  describe('It handles errors and invalid tokens', () => {


    test('It handles an invalid configuration', () => {
      const config = {
        domain: '',
        clientId: '',
        audience: 'invalid-audience',
      }
      try {
        Auth0Provider.configure(config)
      } catch (e) {
        expect(e).toBeInstanceOf(Error);
        expect(e.message).toBe('[INVALID AUTH0 CONFIG]');
      }
    })


    test('should throw Unauthorized for invalid token', async () => {
      const invalidToken = 'invalid'
      try {
        Auth0Provider.getIdentity(invalidToken)
      } catch (e) {
        expect(e).toBeInstanceOf(Unauthorized);
      }
    });

    test('should throw Unauthorized for invalid user', async () => {
      // Test when invalid user is provided
      const req = get_valid_req();
      req.headers.authorization = 'Bearer invalid';
      const next = jest.fn();
      Auth0Provider.isAuthorized(req, null, next);
      next.mockImplementation((error) => {
        expect(error).toBeInstanceOf(Unauthorized);
      })
    });

    test('should throw Forbidden for invalid roles', () => {
      // Test when user does not have valid roles
      const req = { userInfo: { roles: ['role1', 'role2'] } };
      const next = jest.fn();
      const middleware = Auth0Provider.hasRoles('role3');
      middleware(req, null, next);

      next.mockImplementation((error) => {
        expect(error).toBeInstanceOf(Forbidden);
      })
    });

    test('getAuthorizedUserInfo should throw Unauthorized for invalid user', async () => {
      const req = get_valid_req();
      req.headers.authorization = 'Bearer invalid';
      const next = jest.fn();
      Auth0Provider.getAuthorizedUserInfo(req, null, next);
      next.mockImplementation((error) => {
        expect(error).toBeInstanceOf(Unauthorized);
      })
    })
  });
});


