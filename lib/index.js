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

      try {
        var parsedSignature = HttpSignature.parseRequest(req);
        if (!parsedSignature) {
          return reply(Boom.unauthorized('HTTP authentication header missing signature'));
        }
      } catch (e) {
		  return reply(Boom.badRequest(e, 'Signature'));
      }

      settings.validateFunc(request, parsedSignature, function (err, isValid, credentials) {

        credentials = credentials || null;

        if (err) {
          return reply(err, null, {credentials: credentials, log: {tags: ['auth', 'signature'], data: err}});
        }

        if (!isValid) {
          return reply(Boom.unauthorized('Bad signature', 'Signature'), null, {credentials: credentials});
        }

        if (!credentials ||
            typeof credentials !== 'object') {

          return reply(Boom.badImplementation('Bad credentials object received for Signature auth validation'), null, {log: {tags: ['auth', 'credentials']}});
        }

        // Authenticated

        return reply.continue({credentials: credentials});
      });
    },
    payload: function (request, reply) {
      if (settings.payloadFunc) {
        settings.payloadFunc(request, function (err, isValid) {
          if (err) {
            return reply(err, null, {log: {tags: ['auth', 'signature'], data: err}});
          }

          if (!isValid) {
            return reply(Boom.unauthorized('Bad signature', 'Signature'), null, {});
          }
        });
      }

      reply.continue();
    }
  };

  return scheme;
};
