'use strict';

var _ = require('lodash');
var B = require('bluebird');
var Boom = require('boom');
var Hoek = require('hoek');
var Joi = require('joi');
var yarp = require('yarp');

var internals = {
  options: Joi.object({
    url: Joi.string().uri().required(),
    method: Joi.string().only('GET', 'POST').optional().default('GET'),
    auth: Joi.object({
      username: Joi.string().required(),
      password: Joi.string().required()
    }).optional(),
    objectName: Joi.string().allow('', null).optional().default('credentials'),
    responseObjectName: Joi.string().allow('', null).optional().default('credentials'),
    otherData: Joi.object().optional().default(null),
    usernameProperty: Joi.string().optional().default('username'),
    passwordProperty: Joi.string().optional().default('password'),
    tokenProperty: Joi.string().optional().default('token'),
    cache: Joi.object().unknown().allow(null).optional().default(null)
  })
};

internals.implementation = function(server, options) {
  Hoek.assert(options, 'Missing who-dat auth strategy options');
  var validation = internals.options.validate(options);

  Hoek.assert(!validation.error, 'Options not valid: ' + validation.error);

  var settings = validation.value;

  var generateFunc = function generateFunc(id, next) {
    B.try(function() {
      var parts = id.split(/\s+/);

      if (parts.length !== 2) {
        throw Boom.badRequest('Bad HTTP authentication header format', 'Basic');
      }

      var username;
      var requestCreds = {};

      var type = parts[0].toLowerCase();

      if (type === 'basic') {
        var credentialsPart = new Buffer(parts[1], 'base64').toString();
        var sep = credentialsPart.indexOf(':');
        if (sep === -1) {
          throw Boom.badRequest('Bad header internal syntax', 'Basic');
        }

        username = credentialsPart.slice(0, sep);
        var password = credentialsPart.slice(sep + 1);

        if (!username || !password) {
          throw Boom.unauthorized('HTTP authentication header missing username or password', 'Basic');
        }

        requestCreds[settings.usernameProperty] = username;
        requestCreds[settings.passwordProperty] = password;
      } else if (type === 'bearer') {
        requestCreds[settings.tokenProperty] = parts[1];
      } else {
        throw Boom.badRequest('Bad HTTP authentication header format', 'Basic');
      }

      var authRequest = {
        url: settings.url,
        method: settings.method
      };

      if (settings.auth) {
        authRequest.auth = settings.auth;
      }

      if (settings.method === 'POST') {
        if (settings.objectName) {
          authRequest.json = {};
          authRequest.json[settings.objectName] = requestCreds;
        } else {
          authRequest.json = requestCreds;
        }
      } else {
        authRequest.qs = requestCreds;
      }

      return B.join(yarp(authRequest), username);
    }).spread(function(resp, username) {
      var credentials = settings.responseObjectName
        ? resp[settings.responseObjectName]
        : resp;

      if (credentials.authenticated !== true) {
        throw Boom.unauthorized('Bad username or password', 'whodat');
      }

      if (username) {
        credentials.id = username;
      }

      return credentials;
    }).nodeify(next);
  };

  var cachePolicy;
  if (settings.cache) {
    cachePolicy = server.cache(Hoek.applyToDefaults(settings.cache, { generateFunc: generateFunc }));
  } else {
    cachePolicy = {
      get: generateFunc
    };
  }

  var getCredentials = B.promisify(cachePolicy.get, cachePolicy);

  return {
    authenticate: function(request, reply) {
      var authorization = request.raw.req.headers.authorization;
      if (!authorization) {
        return reply(Boom.unauthorized(null, 'Basic'));
      }

      getCredentials(authorization).then(function(credentials) {
        if (_.isArray(credentials)) {
          credentials = credentials[0];
        }

        reply.continue({ credentials: credentials });
      }).catch(reply);
    }
  };
};

exports.register = function(plugin, options, next) {
  plugin.auth.scheme('whodat', internals.implementation);
  next();
};

exports.register.attributes = {
  pkg: require('../package.json')
};
