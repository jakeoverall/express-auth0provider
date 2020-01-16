import jwt from "express-jwt";
import jwksRsa from "jwks-rsa";
import axios from "axios";
import Cache from "node-cache";
import { Forbidden } from "./Forbidden";

const userInfoCache = new Cache({ stdTTL: 60 * 60 });

let authConfig = {
  domain: "",
  clientId: "",
  audience: ""
};

const JWT_OPTIONS = {
  secret: jwksRsa.expressJwtSecret({
    cache: true,
    rateLimit: true,
    jwksRequestsPerMinute: 5,
    jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`
  }),

  audience: authConfig.audience,
  issuer: `https://${authConfig.domain}/`,
  algorithm: ["RS256"]
};

/**
 * @typedef {( error?: Error | string ) => void } NextFunction
 */

export class Auth0Provider {
  /**
   * Configure with your Auth0 credentials
   * @param {{ domain: string; clientId: string; audience: string; }} config
   */
  configure({ domain, clientId, audience }) {
    if (!domain || !clientId || !audience) {
      throw new Error("[INVALID AUTH0 CONFIG]");
    }
    authConfig = { domain, clientId, audience };
  }

  /**
   * Express Middleware:
   *
   * Will validate a user token and extend req to include
   *
   * req.user : { Identity }
   *
   * onerror : next(e)
   *
   * onsuccess : calls next()
   *
   * @param {any} req
   * @param {any} res
   * @param {NextFunction} next
   */
  isAuthorized(req, res, next) {
    return jwt({ ...JWT_OPTIONS, credentialsRequired: true })(req, res, next);
  }

  /**
   * Express Middleware:
   *
   * Enable RBAC: Required or Extended Rules
   * Will validate a user token and ensure the user roles exists on the token and extends req to include
   *
   * req.user : { Identity },
   * req.userInfo : { UserInfo }
   *
   * onerror : next(e)
   *
   * onsuccess : calls next()
   *
   * @param {string[] | string} roles
   * @returns {{(req:any, res:any, next:NextFunction)}} Express.Routehandler
   */
  hasRoles(roles) {
    return (req, res, next) => {
      const validateRoles = () => {
        try {
          if (typeof roles == "string") {
            roles = [roles];
          }

          for (let i = 0; i < roles.length; i++) {
            let p = roles[i];
            if (!req.user.roles.includes(p)) {
              throw new Forbidden("Invalid roles");
            }
          }

          return next();
        } catch (e) {
          next(e);
        }
      };
      this.getAuthorizedUserInfo(req, res, validateRoles);
    };
  }

  /**
   * Express Middleware:
   *
   * Will validate a user token and ensure the user permissions exists on the token and extends req to include
   *
   * req.user : { Identity },
   * req.userInfo : { UserInfo }
   *
   * onerror : next(e)
   *
   * onsuccess : calls next()
   *
   * @param {string[] | string} permissions
   * @returns {{(req:any, res:any, next:NextFunction)}} Express.Routehandler
   */
  hasPermissions(permissions) {
    return (req, res, next) => {
      const validatePermissions = () => {
        try {
          if (typeof permissions == "string") {
            permissions = [permissions];
          }

          for (let i = 0; i < permissions.length; i++) {
            let p = permissions[i];
            if (!req.user.permissions.includes(p)) {
              throw new Forbidden("Invalid Permissions");
            }
          }

          return next();
        } catch (e) {
          next(e);
        }
      };
      this.getAuthorizedUserInfo(req, res, validatePermissions);
    };
  }

  /**
   * Express Middleware:
   *
   * Will validate a user token and extend req to include
   *
   * req.user : { Identity },
   * req.userInfo : { UserInfo }
   *
   * onerror : next(e)
   *
   * onsuccess : calls next()
   *
   * @param {any} req
   * @param {any} res
   * @param {NextFunction} next
   */
  async getAuthorizedUserInfo(req, res, next) {
    return (req, res, next) => {
      const getUserInfo = async () => {
        try {
          if (userInfoCache.has(req.user.sub)) {
            req.userInfo = userInfoCache.get(req.user.sub);
            req.userInfo.fromCache = true;
            return next();
          }
          let res = await axios.get(`https://${authConfig.domain}/userinfo`, {
            headers: {
              authorization: req.headers.authorization
            }
          });
          let userInfo = {};
          for (var key in res.data) {
            let keep = key;
            if (key.includes("https")) {
              keep = keep.slice(keep.lastIndexOf("/") + 1);
            }
            userInfo[keep] = res.data[key];
          }
          req.userInfo = userInfo;
          userInfoCache.set(req.user.sub, req.userInfo);
          next();
        } catch (e) {
          next(e);
        }
      };
      this.isAuthorized(req, res, getUserInfo);
    };
  }
}

export const auth0Provider = new Auth0Provider();
