/**
 * Add common namespaced properties to userInfo, 
 * note auth0 will strip any non namespaced properties
 */
function extendUserInfo(user, context, callback) {
    const uuid = require('uuid@3.3.2');
    const namespace = 'https://YOURDOMAINHERE.auth0.com';
    context.idToken = context.idToken || {};
    context.authorization = context.authorization || {}
    user.app_metadata = user.app_metadata || { new: true };
    user.app_metadata.id = user.app_metadata.id || uuid();

    for (const key in user.app_metadata) {
        context.idToken[`${namespace}/${key}`] = user.app_metadata[key]
    }
    context.idToken[`${namespace}/roles`] = context.authorization.roles
    context.idToken[`${namespace}/permissions`] = context.authorization.permissions
    context.idToken[namespace + '/user_metadata'] = user.user_metadata;
    
    if(!user.app_metadata.new){
        return callback(null, user, context);
    }
    delete user.app_metadata.new
    auth0.users.updateAppMetadata(user.user_id, user.app_metadata)
        .then(function () {
            callback(null, user, context);
        })
        .catch(function (err) {
            callback(err);
        });
}