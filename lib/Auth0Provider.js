const { auth } = require('express-oauth2-jwt-bearer');
const https = require('https');
const jsonwebtoken = require('jsonwebtoken');
const Cache = require('node-cache');
const { BadRequest, Forbidden, Unauthorized } = require('./Errors.js');

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

function request(url, options) {
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
          reject(new BadRequest('Malformed or Expired Token'));
        }
      });
    }).on("error", (err) => {
      reject(err);
    });
  });
}

class Auth0Provider {
  static configure({ domain, clientId, audience },
    options = { dontStrip: false, stdTTL: 60 }
  ) {
    if (!domain || !clientId || !audience) {
      throw new Error("[INVALID AUTH0 CONFIG]");
    }
    authConfig = { domain, clientId, audience, ...options };
    userInfoCache = new Cache({ ...options });
  }

  /**
  * Strips URL-based claims from an object, flattening the structure by removing URLs.
  * Dynamically tracks stripped properties and merges them into top-level arrays.
  * @param {Object} userData - The object containing user claims.
  * @returns {Object} - The object with URLs stripped from the keys and appropriate merging of properties.
  */
  static stripUrlBasedClaims(userData) {
    for (const key in userData) {
      if (userData.hasOwnProperty(key)) {

        // Strip URLs from keys and keep the final part of the URL as the key
        if (!key.includes("http")) {
          continue
        }

        let keep = key.slice(key.lastIndexOf("/") + 1);
        userData[keep] = userData[keep] || userData[key];

        // Handle id merging into a top-level ids array
        if (keep === 'id') {
          userData.ids = userData.ids || []
          userData.ids.push(userData[key]);
          continue
        }


        if (Array.isArray(userData[keep])) {
          const value = Array.isArray(userData[key]) ? userData[key] : [userData[key]]
          userData[keep] = [...userData[keep], ...value];
        }
      }
    }

    for (const key in userData) {
      if (userData.hasOwnProperty(key)) {
        if (Array.isArray(userData[key])) {
          userData[key] = [...new Set(userData[key])];
        }
      }
    }

    // If there are multiple ids, set the top-level id to the first one
    if (userData.ids) {
      userData.id = userData.id || userData.ids[0];
      if (userData.ids.length === 1) {
        delete userData.ids
      }
    }

    return userData;
  }

  /**
 * Middleware to check if the user is authorized.
 * This method ensures `req.user` is populated based on the token claims.
 */
  static isAuthorized(req, res, next) {
    const checkJwt = auth(getJwtOptions());
    checkJwt(req, res, (err) => {
      if (err) {
        return next(err);
      }

      try {
        if (!req.auth || !req.auth.payload) {
          return next(new Unauthorized('Invalid token or missing user info'));
        }

        // Strip URL-based claims from the payload
        req.user = Auth0Provider.stripUrlBasedClaims(req.auth.payload);

        next();
      } catch (e) {
        next(e);
      }
    });
  }

  /**
   * Middleware to check if the user has specific roles.
   * If `req.user` is not set, it will call `isAuthorized` first.
   */
  static hasRoles(roles) {
    return (req, res, next) => {
      if (!req.user) {
        // Call `isAuthorized` first if `req.user` is not set
        Auth0Provider.isAuthorized(req, res, (err) => {
          if (err) return next(err);
          Auth0Provider._validateRoles(req, res, next, roles);
        });
      } else {
        Auth0Provider._validateRoles(req, res, next, roles);
      }
    };
  }

  /**
   * Private method to validate roles.
   * @param {any} req
   * @param {any} res
   * @param {Function} next
   * @param {string[]} roles
   */
  static _validateRoles(req, res, next, roles) {
    Auth0Provider.getAuthorizedUserInfo(req, res, (err) => {
      if (err) {
        return next(err);
      }

      roles = Array.isArray(roles) ? roles : [roles];
      const hasRequiredRole = roles.some(role => req.userInfo.roles.includes(role));
      if (!hasRequiredRole) {
        return next(new Forbidden("Invalid roles"));
      }
      next();
    });
  }

  /**
   * Middleware to check if the user has specific permissions.
   * If `req.user` is not set, it will call `isAuthorized` first.
   */
  static hasPermissions(permissions) {
    return (req, res, next) => {
      if (!req.user) {
        // Call `isAuthorized` first if `req.user` is not set
        Auth0Provider.isAuthorized(req, res, (err) => {
          if (err) return next(err);
          Auth0Provider._validatePermissions(req, res, next, permissions);
        });
      } else {
        Auth0Provider._validatePermissions(req, res, next, permissions);
      }
    };
  }

  /**
   * Private method to validate permissions.
   * @param {any} req
   * @param {any} res
   * @param {Function} next
   * @param {string[]} permissions
   */
  static _validatePermissions(req, res, next, permissions) {
    Auth0Provider.getAuthorizedUserInfo(req, res, (err) => {
      if (err) {
        return next(err);
      }

      permissions = Array.isArray(permissions) ? permissions : [permissions];
      const hasRequiredPermission = permissions.some(permission => req.user.permissions.includes(permission));
      if (!hasRequiredPermission) {
        return next(new Forbidden("Invalid Permissions"));
      }
      next();
    });
  }

  static _getAuthorizedUserInfo(req, res, next) {
    if (userInfoCache.has(req.user.sub)) {
      req.userInfo = userInfoCache.get(req.user.sub);
      req.userInfo.fromCache = true;
      return next();
    }

    Auth0Provider.getUserInfoFromBearerToken(req.headers.authorization)
      .then(userInfo => {
        userInfoCache.set(req.user.sub, userInfo);
        req.userInfo = userInfo;
        next();
      })
      .catch(next);
  }

  /**
   * Fetches the authorized user's information from Auth0, caching it for efficiency.
   * Populates `req.userInfo` with the user's information.
   */
  static getAuthorizedUserInfo(req, res, next) {
    if (!req.user) {
      // Call `isAuthorized` first if `req.user` is not set
      Auth0Provider.isAuthorized(req, res, (err) => {
        if (err) return next(err);
        Auth0Provider._getAuthorizedUserInfo(req, res, next);
      });
    } else {
      Auth0Provider._getAuthorizedUserInfo(req, res, next);
    }
  }

  /**
   * Fetches user information from the bearer token by making an external request to Auth0.
   * Merges permissions from scoped properties (URLs) into a top-level `permissions` array.
 */
  static async getUserInfoFromBearerToken(bearerToken = "") {
    if (typeof bearerToken !== "string" || !bearerToken.includes("Bearer")) {
      throw new BadRequest("Bad Input");
    }

    const claims = this.getClaimsFromToken(bearerToken);

    if (!claims || !claims.sub) {
      throw new Unauthorized("Invalid token, claims do not contain a sub.");
    }

    const cachedUser = userInfoCache.get(claims.sub);
    if (cachedUser) {
      return cachedUser;
    }

    const data = await request(`https://${authConfig.domain}/userinfo`, {
      headers: {
        authorization: bearerToken
      }
    });

    if (authConfig.dontStrip) {
      return data;
    }

    // Strip URL-based claims from the user info data
    let userInfo = Auth0Provider.stripUrlBasedClaims(data);
    userInfoCache.set(userInfo.sub, { ...claims, ...userInfo });

    return { ...userInfo, ...claims };
  }

  /**
   * Extracts the claims from a JWT token.
   * @param {string} token - The JWT token.
   * @returns {Object} - The claims from the token.
   */
  static getClaimsFromToken(token = '') {
    if (token.startsWith('Bearer')) {
      token = token.slice(7);
    }
    const { payload } = jsonwebtoken.decode(token, { complete: true }) || { payload: {} };
    return payload;
  }

  /**
   * Removes a user from the cache.
   */
  static removeUserFromCache(sub) {
    userInfoCache.del(sub);
  }

  /**
   * Clears all user data from the cache.
   */
  static clearUserCache() {
    userInfoCache.flushAll();
  }

  static MOCKED = false
}

module.exports = { Auth0Provider };
