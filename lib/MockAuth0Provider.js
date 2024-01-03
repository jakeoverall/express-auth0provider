const { Unauthorized } = require('./Errors.js');
const { Auth0Provider } = require('./Auth0Provider.js');

class MockAuth0Provider {
  constructor() {
    Auth0Provider.isAuthorized = this.mockIsAuthorized.bind(this);
    Auth0Provider.getAuthorizedUserInfo = this.mockGetAuthorizedUserInfo.bind(this);
    Auth0Provider.getUserInfoFromBearerToken = this.mockGetUserInfoFromBearerToken.bind(this);
    Auth0Provider.MOCKED = true;
    this.mockedUser = null;
    this.mockedUserInfo = null;
  }

  mockIsAuthorized(req, res, next) {
    try {
      if (!this.mockedUser) {
        throw new Unauthorized('[Invalid Auth] Mock User was not set');
      }
      req.user = this.mockedUser;
      next();
    } catch (e) {
      next(e);
    }
  }

  mockGetAuthorizedUserInfo(req, res, next) {
    this.mockIsAuthorized(req, res, () => {
      const base = {
        roles: [],
        permissions: [],
      };
      const userInfo = this.mockedUserInfo || this.mockedUser || {};
      req.userInfo = { ...base, ...userInfo };
      next();
    });
  }

  mockGetUserInfoFromBearerToken(bearerToken = '') {
    return this.mockedUserInfo;
  }

  setMockUser(user) {
    this.mockedUser = user;
  }

  setMockUserInfo(userInfo) {
    this.mockedUser = userInfo;
    this.mockedUserInfo = userInfo;
  }
}

module.exports = { MockAuth0Provider };