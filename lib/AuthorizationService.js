import { auth } from 'express-oauth2-jwt-bearer';
import https from "https";
import jsonwebtoken from 'jsonwebtoken';
import Cache from "node-cache";
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
    audience: authConfig.audience,
    issuerBaseURL: `https://${authConfig.domain}/`
  };
}

async function request(url, options) {
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
          reject({ message: 'Malformed or Expired Token', data, response: res })
        }
      });
    }).on("error", (err) => {
      reject(err);
    });
  });
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
   * Will validate a user token and extend req to include
   * req.user : { Identity }
   * onerror : next(e)
   * onsuccess : calls next()
   * @param {any} req
   * @param {any} res
   * @param {NextFunction} next
   */
  static isAuthorized(req, res, next) {
    return ((req, res, next) => {
      if (req.user) { return next() }
      const checkJwt = auth(getJwtOptions());
      // @ts-ignore
      checkJwt(
        req,
        res,
        (err, _, __, ___) => {
          if (err) {
            return next(err);
          }
          try {
            req.user = req.auth.payload
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

    return new Promise(async (resolve, reject) => {

      if (typeof bearerToken != "string") {
        return reject(new BadRequest("Bad Input"))
      }
      if (!bearerToken.includes("Bearer")) {
        bearerToken = "Bearer " + bearerToken;
      }
      const claims = jsonwebtoken.decode(bearerToken.slice(7), { complete: true }) || { payload: {} }

      try {
        // @ts-ignore
        if (userInfoCache.has(claims.payload.sub)) {
          // @ts-ignore
          return resolve(userInfoCache.get(claims.payload.sub))
        }
        let data = await request(`https://${authConfig.domain}/userinfo`, {
          headers: {
            authorization: bearerToken
          }
        });
        let userInfo = {};
        if (authConfig.dontStrip) {
          return resolve(data);
        }
        for (var key in data) {
          let keep = key;
          if (key.includes("https")) {
            keep = keep.slice(keep.lastIndexOf("/") + 1);
          }
          userInfo[keep] = data[key];
        }
        // @ts-ignore
        userInfo.permissions = claims.payload.permissions || []
        userInfoCache.set(userInfo.sub, userInfo);
        return resolve(userInfo);
      } catch (e) {
        reject(new Unauthorized("[unable to validate bearer token] " + e.message));
      }
    })
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


