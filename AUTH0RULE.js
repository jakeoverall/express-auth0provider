//AUTH0 RULE
/**
 * Add common namespaced properties to userInfo, 
 * note auth0 will strip any non namespaced properties
 */
 function extendUserInfo(user, context, callback) {
    const namespace = 'https://YOURDOMAINHERE.auth0.com';
    context.idToken = context.idToken || {};
    context.authorization = context.authorization || {};
    user.app_metadata = user.app_metadata || { };
    user.app_metadata.new = user.app_metadata.id ? false : true;
    user.app_metadata.id = user.app_metadata.id || generateId();

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
  
  function generateId() {
    let timestamp = (new Date().getTime() / 1000 | 0).toString(16);
    return timestamp + 'xxxxxxxxxxxxxxxx'.replace(/[x]/g, () => (
      Math.random() * 16 | 0).toString(16)).toLowerCase();
	}
}