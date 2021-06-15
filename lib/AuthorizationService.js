import axios from "axios";
import jwt from "express-jwt";
import jwksRsa from "jwks-rsa";
import Cache from "node-cache";
import jsonwebtoken from 'jsonwebtoken'
import { BadRequest, Forbidden, Unauthorized } from "./Errors.js";

let userInfoCache = new Cache({ stdTTL: 60 * 5 });

let authConfig = {
  domain: "",
  clientId: "",
  audience: "",
  dontStrip: false
};

function getJwtOptions() {
  return {
    secret: jwksRsa.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${authConfig.domain}/.well-known/jwks.json`,
    }),
    audience: authConfig.audience,
    issuer: `https://${authConfig.domain}/`,
    algorithms: ["RS256"]
  };
}

/**
 * @typedef {( error?: Error | string ) => void } NextFunction
 */

export class Auth0Provider {
  /**
   * Configure with your Auth0 credentials
   * @param {{ domain: string; clientId: string; audience: string; }} config
   */
  static configure(
    { domain, clientId, audience },
    options = { dontStrip: false, stdTTL: 60 }
  ) {
    if (!domain || !clientId || !audience) {
      throw new Error("[INVALID AUTH0 CONFIG]");
    }
    authConfig = { domain, clientId, audience, ...options };
    userInfoCache = new Cache({ ...options });
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
  static isAuthorized(req, res, next) {
    return ((req, res, next) => {
      if(req.user){return next()}
      jwt({ ...getJwtOptions(), credentialsRequired: true })(
        req,
        res,
        (err, _, __, ___) => {
          if (err) {
            return next(err);
          }
          try {
            for (var key in req.user) {
              let keep = key;
              if (key.includes("https")) {
                keep = keep.slice(keep.lastIndexOf("/") + 1);
              }
              req.user[keep] = req.user[key];
            }
            next();
          } catch (e) {
            next(e);
          }
        }
      );

    })(req, res, next);
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
  static hasRoles(roles) {
    return (req, res, next) => {
      const validateRoles = (err) => {
        try {
          if (err instanceof Error) {
            throw err;
          }
          if (typeof roles == "string") {
            roles = [roles];
          }

          for (let i = 0; i < roles.length; i++) {
            let p = roles[i];
            if (!req.userInfo.roles.includes(p)) {
              throw new Forbidden("Invalid roles");
            }
          }

          return next();
        } catch (e) {
          next(e);
        }
      };
      Auth0Provider.getAuthorizedUserInfo(req, res, validateRoles);
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
  static hasPermissions(permissions) {
    return (req, res, next) => {
      const validatePermissions = (err) => {
        try {
          if (err instanceof Error) {
            throw err;
          }
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
      Auth0Provider.getAuthorizedUserInfo(req, res, validatePermissions);
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
  static async getAuthorizedUserInfo(req, res, next) {
    const getUserInfo = async (err) => {
      try {
        if (err instanceof Error) {
          throw err;
        }
        if (userInfoCache.has(req.user.sub)) {
          req.userInfo = userInfoCache.get(req.user.sub);
          req.userInfo.fromCache = true;
          return next();
        }
        req.userInfo = await Auth0Provider.getUserInfoFromBearerToken(
          req.headers.authorization
        );
        userInfoCache.set(req.user.sub, req.userInfo);
        next();
      } catch (e) {
        next(e);
      }
    };
    Auth0Provider.isAuthorized(req, res, getUserInfo);
  }

  /**
   * Validates and returns userInfo from a BearerToken
   * @param {string} bearerToken
   */
  static async getUserInfoFromBearerToken(bearerToken = "") {
    if (typeof bearerToken != "string") {
      throw new BadRequest("Bad Input")
    }
    if (!bearerToken.includes("Bearer")) {
      bearerToken = "Bearer " + bearerToken;
    }
    const claims = jsonwebtoken.decode(bearerToken.slice(7), { complete: true }) || { payload: {} }
    
    try {
      if (userInfoCache.has(claims.payload.sub)) {
        return userInfoCache.get(claims.payload.sub)
      }
      let res = await axios.get(`https://${authConfig.domain}/userinfo`, {
        headers: {
          authorization: bearerToken
        }
      });
      let userInfo = {};
      if (authConfig.dontStrip) {
        return res.data;
      }
      for (var key in res.data) {
        let keep = key;
        if (key.includes("https")) {
          keep = keep.slice(keep.lastIndexOf("/") + 1);
        }
        userInfo[keep] = res.data[key];
      }
      // @ts-ignore
      userInfo.permissions = claims.payload.permissions || []
      userInfoCache.set(userInfo.sub, userInfo);
      return userInfo;
    } catch (e) {
      throw new Unauthorized("[unable to validate bearer token] " + e.message);
    }
  }

  /**
  * Removes a user from the cache
  * @param {string} sub
  */
  static removeUserFromCache(sub) {
    userInfoCache.del(sub);
  }

  static clearUserCache() {
    userInfoCache.flushAll();
  }

  static MOCKED = false

}


