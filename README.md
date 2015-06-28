### hapi-auth-signature

NOTE: Use v1.0.1 from npm for Hapi version 7.x.x and v2.x.x for Hapi version 8.x.x

NOTE: In version 0.11.0 of [http-signature](https://github.com/joyent/node-http-signature) the verify method has been split into `verifyHMAC` and `verifySignature`. The example below uses an HMAC scheme, and so the verify function is using `verifyHMAC`. 

First, a big hat tip to the guys that created the [hapi](http://hapijs.com/) framework.

This is a signature authentication scheme for [hapi](http://hapijs.com/) that wraps the [Joyent Signature Authentication Scheme](https://github.com/joyent/node-http-signature) and requires a validating signed authorization header. (Note: the format of this plugin, including the docs here, follows the [hapi-auth-basic](https://github.com/hapijs/hapi-auth-basic) plugin).

The hapi-auth-signature scheme takes the following options.

- `validateFunc` - (required) validation function with the signature `function(request, parsedSignature, callback)` where:
    - `request` - hapi request object.
    - `parsedSignature` - [http-signature](https://github.com/joyent/node-http-signature) parsed signature from header.
    - `callback` - a callback function with the signature `function(err, isValid, credentials)` where:
        - `err` - an internal error.
        - `isValid` - `true` if the signature is verified, otherwise `false`.
        - `credentials` - a credentials object passed back to the application in `request.auth.credentials`. Typically, `credentials` are only
          included when `isValid` is `true`, but there are cases when the application needs to know who tried to authenticate even when it fails
          (e.g. with authentication mode `'try'`).

The validation function shown below is based on an hmac strategy with a key identifier and secret key stored in a user record. [http-signature](https://github.com/joyent/node-http-signature) supports the following algorithms:

* rsa-sha1
* rsa-sha256
* rsa-sha512
* dsa-sha1
* hmac-sha1
* hmac-sha256
* hmac-sha512

Public key algorithms will almost certainly require their own validating function (and therefore strategy). The algorithm used can be retrieved from the header as it's part of the http-signature scheme. See the docs at  [http-signature](https://github.com/joyent/node-http-signature) for more details.

```javascript

var HttpSignature = require('http-signature');

var users = [
    {
        id: 1,
        username: 'john',
        apikeyid: '18KF2FGK6807ZQA945R2',
        secretkey: '46573e78ce9df4f2d9ae93afd5f5c281'
    }
];

var validate = function (request, parsedSignature, callback) {

    var keyId = parsedSignature.keyId;
    var credentials = {};
    var secretKey;
    users.forEach(function(user, index) {
        if (user.apikeyid === keyId) {
            secretKey = user.secretkey;
            credentials = {id: user.id, username: user.username};
        }
    });

    if (!secretKey) {
        return callback(null, false);
    }

    if(HttpSignature.verifyHMAC(parsedSignature, secretKey)) {
        callback(null, true, credentials);
    } else {
        callback(null, false);
    };
};

server.pack.register(require('hapi-auth-signature'), function (err) {

    server.auth.strategy('hmac', 'signature', { validateFunc: validate });
    server.route({ method: 'GET', path: '/', config: { auth: 'hmac' } });
});

```