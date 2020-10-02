import { Auth0Provider } from "./AuthorizationService";
import { Unauthorized } from "./Errors";


/**
 * @typedef {( error?: Error | string ) => void } NextFunction
 */

/**
 * Used to override the default functionality of Auth0Provider for a test environment
 */

export class MockAuth0Provider {
  constructor() {
    Auth0Provider.isAuthorized = this.isAuthorized.bind(this);
    Auth0Provider.getAuthorizedUserInfo = this.getAuthorizedUserInfo.bind(this);
    Auth0Provider.getUserInfoFromBearerToken = this.getUserInfoFromBearerToken.bind(this);
    Auth0Provider.MOCKED = true;
    this.MOCKED_USER = null;
    this.MOCKED_USER_INFO = null;
  }

  /**
   * Sets the req.user to the MOCKED_USER
   * @param {any} req
   * @param {any} res
   * @param {NextFunction} next 
   */
  isAuthorized(req, res, next) {
    try {
      if (!this.MOCKED_USER) {
        throw new Unauthorized("[Invalid Auth] Mock User was not set");
      }
      req.user = this.MOCKED_USER;
      next();
    } catch (e) {
      next(e)
    }
  }

  /**
   * Sets the req.userInfo to the MOCKED_USER_INFO
   * @param {any} req
   * @param {any} res
   * @param {NextFunction} next
   */
  getAuthorizedUserInfo(req, res, next) {
    this.isAuthorized(req, res, () => {
      let base = {
        roles: [],
        permissions: []
      }
      let mockUser = this.MOCKED_USER_INFO || this.MOCKED_USER || {}
      req.userInfo = { ...base, ...mockUser };
      next()
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
   * @param {{ sub:string, email:string, [x:string]:any }} user
   */
  setMockUser(user) {
    this.MOCKED_USER = user;
  }

  /**
   * Sets the MOCKED_USER and MOCKED_USER_INFO. Mandatory for using roles and permission based middleware
   * @param {{ sub:string, email:string, permissions: string[], roles: string[], [x:string]:any }} userInfo
   */
  setMockUserInfo(userInfo) {
    this.MOCKED_USER = userInfo;
    this.MOCKED_USER_INFO = userInfo;
  }

}
