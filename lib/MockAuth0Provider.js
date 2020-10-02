import { Auth0Provider } from "./AuthorizationService";

/**
 * Used to override the default functionality of Auth0Provider for a test environment
 */

export class MockAuth0Provider {
  constructor() {
    Auth0Provider.isAuthorized = this.isAuthorized;
    Auth0Provider.getAuthorizedUserInfo = this.getAuthorizedUserInfo;
    Auth0Provider.getUserInfoFromBearerToken = this.getUserInfoFromBearerToken;
    Auth0Provider.MOCKED = true;
    this.MOCKED_USER = null;
    this.MOCKED_USER_INFO = null;
  }

  /**
   * Sets the req.user to the MOCKED_USER
   */
  isAuthorized(req, res, next) {
    if (!this.MOCKED_USER) {
      next("[Invalid Auth] Mock User was not set");
    }
    req.user = this.MOCKED_USER;
    next();
  }

  /**
   * Sets the req.userInfo to the MOCKED_USER_INFO
   */
  getAuthorizedUserInfo(req, res, next) {
    this.isAuthorized(req, res, () => {
      req.userInfo = this.MOCKED_USER_INFO || this.MOCKED_USER;
    });
  }

  /**
   * returns the MOCKED_USER_INFO, bearerToken is ignored
   * @param {string} bearerToken
   */
  getUserInfoFromBearerToken(bearerToken = "") {
    return this.MOCKED_USER_INFO;
  }

  /**
   *
   * @param {{ sub:string, email:string, [picture]:string }} user
   */
  setMockUser(user) {
    this.MOCKED_USER = user;
  }

  /**
   * Sets the MOCKED_USER and MOCKED_USER_INFO. Mandatory for using roles and permission based middleware
   * @param {{ sub:string, email:string, permissions: string[], roles: string[], [picture]:string }} userInfo
   */
  setMockUserInfo(userInfo) {
    this.MOCKED_USER = user;
    this.MOCKED_USER_INFO = userInfo;
  }

}
