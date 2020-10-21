# @bcwdev/auth0Provider

This library provides easily configured middleware that will validate user auth tokens, roles, permissions and provides a simple approach to get userInfo associted with a user account. Each middleware will call next with an error on any failure so be sure to setup a default error handler. Also note that we extend the express request object with

- req.user: `{ UserIdentity }`
- req.userInfo: `{ UserInfo }`

### Enable RBAC or Extended Rules (required)

In your auth0 dashboard be sure to enable RBAC or add in this custom rule

```javascript
//AUTH0 RULE
/**
 * Add common namespaced properties to userInfo, 
 * note auth0 will strip any non namespaced properties
 */
function extendUserInfo(user, context, callback) {
    const uuid = require('uuid@3.3.2');
    const namespace = 'https://YOURDOMAINHERE.auth0.com';
    context.idToken = context.idToken || {};
    context.authorization = context.authorization || {};
    user.app_metadata = user.app_metadata || { new: true };
    user.app_metadata.id = user.app_metadata.id || uuid();

    for (const key in user.app_metadata) {
        context.idToken[`${namespace}/${key}`] = user.app_metadata[key];
    }
    context.idToken[`${namespace}/roles`] = context.authorization.roles;
    context.idToken[`${namespace}/permissions`] = context.authorization.permissions;
    context.idToken[`${namespace}/user_metadata`] = user.user_metadata;
    
    if(!user.app_metadata.new){
        return callback(null, user, context);
    }
    delete user.app_metadata.new;
    auth0.users.updateAppMetadata(user.user_id, user.app_metadata)
        .then(function () {
            callback(null, user, context);
        })
        .catch(function (err) {
            callback(err);
        });
}
```

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
  .get("/blogs", this.getAll)
  .use(Auth0Provider.isAuthorized)
  // everything below this point requires authorization
  .get("/blogs/:id", this.getById);
  .put("/blogs/:id", this.updateById);
  .use(Auth0Provider.hasPermission("delete:blog"))
  // requires permission to reach this point
  .delete("/blogs/:id", this.deleteById);
```


---------

#### Mocking the Middleware

Production code can be directly tested by mocking the behavior of Auth0Provider, overriding the need for a bearer token and directly setting the user.

```javascript
// BlogsController.spec.js
import { MockAuth0Provider } from "@bcw/auth0-server";

const AUTH_MOCK = new MockAuth0Provider()

const USERS = {
  user_billy: { sub: "122", email: "Billy Tester", roles: ['user'], permissions: [] },
  admin_jimmy: { sub: "123", email: "Jimmy Tester", roles: ['admin'], permissions: ['delete:blog'] }
}


describe("blogs controller"){
    
  it('expects a 403 forbidden when attempting to remove a blog without permission', async ()=>{
    
    // Sets the user without the correct permissions for removing a blog
    AUTH_MOCK.setMockUserInfo(USERS.user_billy)

    let res = await request(app)
                      .delete('/blogs/b174arD')
                      .expect(403)
    // ... 
  })

  it('permission required to delete blog', async ()=>{
    
    // Sets the user bypassing the need for a bearer token
    AUTH_MOCK.setMockUserInfo(USERS.admin_jimmy)

    let res = await request(app)
                      .delete('/blogs/b174arD')
                      .expect(200)
    // ... 
  })

}

```
