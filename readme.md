# @bcwdev/auth0Provider

This library provides easily configured middleware that will validate user auth tokens, roles, permissions and provides a simple approach to get userInfo associted with a user account. Each middleware will call next with an error on any failure so be sure to setup a default error handler. Also note that we extend the express request object with

- req.user: `{ UserIdentity }`
- req.userInfo: `{ UserInfo }`

### Enable RBAC or Extended Rules (required)

In your auth0 dashboard be sure to enable RBAC or add in this custom rule

```javascript
//AUTH0 RULE
function (user, context, callback) {
  // please note auth0 will strip any non namespaced properties
  const namespace = 'https://YOURDOMAIN.auth0.com';
  const assignedRoles = (context.authorization || {}).roles;

  let idTokenClaims = context.idToken || {};

  idTokenClaims[`${namespace}/roles`] = assignedRoles;
  context.idToken = idTokenClaims;
  context.idToken[namespace + '/user_metadata'] = user.user_metadata;
  context.idToken[namespace + '/app_metadata'] = user.app_metadata;

  callback(null, user, context);
}
```

Example of how to use and configure auth0Provider, You can configure the auth0Provider anywhere in your application and then import it and use the middleware anywhere

```javascript
import { auth0Provider } from "@bcw/auth0-server";

auth0Provider.configure({
  domain: process.env.AUTH_DOMAIN,
  clientId: process.env.AUTH_CLIENT_ID,
  audience: process.env.AUTH_AUDIENCE
});

// validates a request has a Bearer auth token in req.headers.authentication
app.use("/authenticated", auth0Provider.isAuthenticated, (req, res, next) => {
  res.send({ userIdentity: req.user });
});

// validates the request token and extracts the userInfo saved in auth0
app.use("/user-profile", getAuthorizedUserInfo, (req, res, next) => {
  res.send({ userIdentity: req.user, userInfo: req.userInfo });
});

// validates the request token, extracts the userIdentity and userInfo
// fails if role is not found in the token
// Enable RBAC or Extended Rules
app.use(
  "/admins-only",
  auth0Provider.hasRoles("admin"),
  (req, res, next) => {}
);

// validates the request token, extracts the userIdentity and userInfo
// fails if any permission is not found in the token
// Enable RBAC or Extended Rules
app.use(
  "/messages",
  auth0Provider.hasPermissions(["read:messages", "write:messages"]),
  (req, res, next) => {}
);

//recommended default error handler
app.use((error, req, res, next) => {
  if (error.status == 500 || !error.status) {
    error.message = console.error(error); // should write to external
  }
  error = error || {
    status: 400,
    message: "An unexpected error occured please try again later"
  };
  res.status(error.status).send({ ...error, url: req.url });
});
```

Using chained methods with express.Router()

```javascript
express
  .Router()
  .get("", this.getAll)
  .use(AuthorizationService.isAuthorized)
  // everything below this point requires authorization
  .get("/:id", this.getById);
  .put("/:id", this.updateById);
  .use(AuthorizationService.hasPermission("delete:blog"))
  // requires permission to reach this point
  .delete("/:id", this.deleteById);
```
