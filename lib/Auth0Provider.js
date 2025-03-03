const { BadRequest, Forbidden, Unauthorized } = require('./Errors.js');
const { SimpleCache } = require('./SimpleCache.js');
const { httpRequest } = require('./httpRequest.js');

let userInfoCache = new SimpleCache();

let authConfig = {
  domain: "",
  clientId: "",
  audience: "",
};


function parseJWT(token) {
  if (!token || typeof token !== 'string') {
    throw new Unauthorized('Invalid or missing token');
  }

  if (token.startsWith('Bearer ')) {
    token = token.slice(7);
  }

  const base64Url = token.split('.')[1] || '';
  if (!base64Url) {
    throw new Unauthorized('Invalid token format');
  }
  const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
  return JSON.parse(Buffer.from(base64, 'base64').toString());
}



class Auth0Provider {
  static configure({ domain, clientId, audience }) {
    if (!domain || !clientId || !audience) {
      throw new Error("[INVALID AUTH0 CONFIG]");
    }
    authConfig = { domain, clientId, audience };
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
    try {
      Auth0Provider.extractJwtIdentity(req);
      next();
    } catch (e) {
      next(e)
    }
  }

  static extractJwtIdentity(req) {
    req.identity = parseJWT(req.headers.authorization);
  }

  /**
   * @param {string | string[]} roles 
   * Middleware to check if the user has specific roles.
   */
  static hasRoles(roles) {
    return (req, res, next) => {
      try {
        Auth0Provider.extractJwtIdentity(req);
        roles = Array.isArray(roles) ? roles : [roles];
        req.identity.roles = req.identity.roles || [];
        req.identity.roles = [...new Set(req.identity.roles)];
        if (roles.some(role => req.identity.roles.includes(role))) {
          return next();
        }
        throw new Forbidden("You don't have the required roles");
      } catch (e) {
        next(e)
      }
    };
  }


  /**
   * @param {string | string[]} permissions
   * Middleware to check if the user has specific permissions.
   */
  static hasPermissions(permissions) {
    return (req, res, next) => {
      try {
        Auth0Provider.extractJwtIdentity(req);
        permissions = Array.isArray(permissions) ? permissions : [permissions];
        req.identity.permissions = req.identity.permissions || [];
        req.identity.permissions = [...new Set(req.identity.permissions)];
        if (permissions.some(permission => req.identity.permissions.includes(permission))) {
          return next();
        }
        throw new Forbidden("You don't have the required permissions");
      } catch (e) {
        next(e)
      }
    };
  }

  /**
   * Fetches the authorized user's information from Auth0, caching it for efficiency.
   */
  static getAuthorizedUserInfo(req, res, next) {
    try {
      Auth0Provider.extractJwtIdentity(req);
    } catch (e) {
      return next(e)
    }
    const sub = req.identity.sub;
    if (!sub) {
      return next(new BadRequest("Invalid token: no subject found in claims, please check your token"));
    }
    let userInfo = userInfoCache.get(sub);
    if (!userInfo) {
      httpRequest(
        `https://${authConfig.domain}/userinfo`,
        {
          headers: {
            Authorization: req.headers.authorization,
          },
        }
      )
        .then((userInfo) => {
          userInfo = this.stripUrlBasedClaims(userInfo);
          req.userInfo = userInfo;
          userInfoCache.set(sub, userInfo);
        })
        .catch((e) => {
          next(e);
        });
    }
  }

  /**
   * @param {string} token
   * extracts the user information from the bearer token.
 */
  static async getIdentity(token = "") {
    const identity = parseJWT(token);
    return identity;
  }

  /**
   * Retrieves user information from the cache.
   */
  static getUserFromCache(sub) {
    return userInfoCache.get(sub);
  }

  /**
   * Removes a user from the cache.
   */
  static removeUserFromCache(sub) {
    userInfoCache.remove(sub);
  }

  /**
   * Clears all user data from the cache.
   */
  static clearUserCache() {
    userInfoCache.flush();
  }
}

module.exports = { Auth0Provider };
