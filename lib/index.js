'use strict';

var _ = require('lodash');
var B = require('bluebird');
var Boom = require('boom');
var Hoek = require('hoek');
var Joi = require('joi');
var yarp = require('yarp');

var internals = {
  defaults: {
    objectName: 'credentials',
    responseObjectName: 'credentials',
    method: 'GET',
    usernameProperty: 'username',
    passwordProperty: 'password',
    tokenProperty: 'token',
    cache: null
  },

  options: Joi.object({
    url: Joi.string().uri().required(),
    method: Joi.string().valid('GET', 'POST'),
    auth: Joi.object({
      username: Joi.string().required(),
      password: Joi.string().required()
    }).optional(),
    objectName: Joi.string().allow('', null).optional(),
    responseObjectName: Joi.string().allow('', null).optional(),
    otherData: Joi.object().optional(),
    usernameProperty: Joi.string(),
    passwordProperty: Joi.string(),
    tokenProperty: Joi.string(),
    cache: Joi.object().unknown().optional().allow(null)
  })
};

internals.implementation = function(server, options) {
  var validateOptions = internals.options.validate(options);
  Hoek.assert(options, 'Missing who-dat auth strategy options');
  Hoek.assert(!validateOptions.error, 'Options not valid: ' + validateOptions.error);

  var settings = Hoek.applyToDefaults(internals.defaults, options, true);

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
      if (resp[settings.responseObjectName].authenticated !== true) {
        throw Boom.unauthorized('Bad username or password', 'Basic');
      }

      var credentials = resp[settings.responseObjectName];
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
