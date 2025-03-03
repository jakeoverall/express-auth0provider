# @bcwdev/auth0Provider

This library provides easily configured middleware that will validate user auth tokens, roles, permissions and provides a simple approach to get userInfo associted with a user account. Each middleware will call next with an error on any failure so be sure to setup a default error handler. Also note that we extend the express request object with

- req.identity: `{ UserIdentity }`
- req.userInfo: `{ UserInfo }`

#### Application Use

Example of how to use and configure auth0Provider, You can configure the auth0Provider anywhere in your application and then import it and use the middleware anywhere

```javascript
import { Auth0Provider } from "@bcw/auth0-server";

Auth0Provider.configure({
  domain: process.env.AUTH_DOMAIN,
  clientId: process.env.AUTH_CLIENT_ID,
  audience: process.env.AUTH_AUDIENCE
});

// validates a request has a Bearer auth token in req.headers.authentication
app.use("/authenticated", Auth0Provider.isAuthenticated, (req, res, next) => {
  res.send({ userIdentity: req.identity });
});

// validates the request token and extracts the userInfo saved in auth0
app.use("/user-profile", getAuthorizedUserInfo, (req, res, next) => {
  res.send({ userIdentity: req.identity, userInfo: req.userInfo });
});

// validates the request token, extracts the userIdentity and userInfo
// fails if role is not found in the token
// Enable RBAC or Extended Rules
app.use(
  "/admins-only",
  Auth0Provider.hasRoles("admin"),
  (req, res, next) => {}
);

// validates the request token, extracts the userIdentity and userInfo
// fails if any permission is not found in the token
// Enable RBAC or Extended Rules
app.use(
  "/messages",
  Auth0Provider.hasPermissions(["read:messages", "write:messages"]),
  (req, res, next) => {}
);

//recommended default error handler
app.use((error, req, res, next) => {
  if (error.statusCode == 500 || !error.statusCode) {
    error.message = console.error(error); // should write to external
  }
  error = error || {
    statusCode: 400,
    message: "An unexpected error occured please try again later"
  };
  res.status(error.statusCode).send({ ...error, url: req.url });
});
```

Using chained methods with express.Router()

```javascript
express
  .Router()
  .get("/blogs", this.getAll)
  .use(Auth0Provider.isAuthorized)
  // everything below this point requires authorization
  .get("/blogs/:id", this.getById);
  .put("/blogs/:id", this.updateById);
  .use(Auth0Provider.hasPermission("delete:blog"))
  // requires permission to reach this point
  .delete("/blogs/:id", this.deleteById);
```