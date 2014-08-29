// Load modules

var Boom = require('boom');
var Hoek = require('hoek');
var HttpSignature = require('http-signature');


// Declare internals

var internals = {};


exports.register = function (plugin, options, next) {

  plugin.auth.scheme('signature', internals.implementation);
  next();
};

exports.register.attributes = {
  pkg: require('../package.json')
};


internals.implementation = function (server, options) {

  Hoek.assert(options, 'Missing signature auth strategy options');
  Hoek.assert(typeof options.validateFunc === 'function', 'options.validateFunc must be a valid function in signature scheme');

  var settings = Hoek.clone(options);

  var scheme = {
    authenticate: function (request, reply) {

      var req = request.raw.req;
      if (!req.headers.authorization) {
        return reply(Boom.unauthorized(null, 'Signature'));
      }

      var parsedSignature = HttpSignature.parseRequest(req);
      if (!parsedSignature) {
        return reply(Boom.unauthorized('HTTP authentication header missing signature', 'Signature'));
      }

      settings.validateFunc(request, parsedSignature, function (err, isValid, credentials) {

        credentials = credentials || null;

        if (err) {
          return reply(err, { credentials: credentials, log: { tags: ['auth', 'signature'], data: err } });
        }

        if (!isValid) {
          return reply(Boom.unauthorized('Bad signature', 'Signature'), { credentials: credentials });
        }

        if (!credentials ||
            typeof credentials !== 'object') {

          return reply(Boom.badImplementation('Bad credentials object received for Signature auth validation'), { log: { tags: ['auth', 'credentials'] } });
        }

        // Authenticated

        return reply(null, { credentials: credentials });
      });
    }
  };

  return scheme;
};