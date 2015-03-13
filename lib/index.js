'use strict';

var Joi = require('joi');
var Hoek = require('hoek');
var yarp = require('yarp');
var Boom = require('boom');
var URL = require('url');

var internals = {
  defaults: {
    objectName: 'credentials',
    responseObjectName: 'credentials',
    method: 'GET',
    usernameProperty: 'username',
    passwordProperty: 'password'
  },
  options: Joi.object({
    url: Joi.string().uri().required(),
    method: Joi.string().valid('GET', 'POST'),
    objectName: Joi.string().allow('', null).optional(),
    responseObjectName: Joi.string().allow('', null).optional(),
    otherData: Joi.object().optional(),
    usernameProperty: Joi.string(),
    passwordProperty: Joi.string(),
    auth: Joi.object({
      username: Joi.string().required(),
      password: Joi.string().required()
    }).optional()
  }),

  extractHeaders: function(request){
    // Straight out of hapi-auth-basic
    var req = request.raw.req;
    var authorization = req.headers.authorization;
    if (!authorization) {
      throw Boom.unauthorized(null, 'Basic');
    }

    var parts = authorization.split(/\s+/);

    if (parts[0].toLowerCase() !== 'basic') {
      throw Boom.unauthorized(null, 'Basic');
    }

    if (parts.length !== 2) {
      throw Boom.badRequest('Bad HTTP authentication header format', 'Basic');
    }

    var credentialsPart = new Buffer(parts[1], 'base64').toString();
    var sep = credentialsPart.indexOf(':');
    if (sep === -1) {
      throw Boom.badRequest('Bad header internal syntax', 'Basic');
    }

    var username = credentialsPart.slice(0, sep);
    var password = credentialsPart.slice(sep + 1);

    if (!username || !password) {
      throw Boom.unauthorized('HTTP authentication header missing username or password', 'Basic');
    }

    return {
      username: username,
      password: password
    };
  }
};

internals.implementation= function(server, options){
  var validateOptions = internals.options.validate(options);
  Hoek.assert(options, 'Missing who-dat auth strategy options');
  Hoek.assert(!validateOptions.error, 'Options not valid: '+validateOptions.error);

  var settings = Hoek.clone(internals.defaults);
  Hoek.merge(settings, options);

  return {
    authenticate: function (request, reply) {
      var creds;
      try{
        creds = internals.extractHeaders(request);
      } catch(e){
        return reply(e);
      }

      var authRequest = {
        url: settings.url,
        method: settings.method,
        json: true
      };

      if(settings.auth){
        authRequest.auth = settings.auth;
      }

      var requestCreds = {};
      requestCreds[settings.usernameProperty] = creds.username;
      requestCreds[settings.passwordProperty] = creds.password;

      switch(settings.method){
      case 'POST':
        authRequest.body = {};
        if(settings.objectName) {
          authRequest.body[settings.objectName] = requestCreds;
        } else {
          authRequest.body = requestCreds;
        }
        break;
      case 'GET':
        var url = URL.parse(authRequest.url, true);
        Hoek.merge(url.query, requestCreds);
        delete url.search;
        authRequest.url = URL.format(url);
        break;
      }

      yarp(authRequest).then(function(resp){
        if(resp.credentials.authenticated===true){
          var credentails = resp.credentials;
          Hoek.merge(credentails, {id: creds.username});
          return reply.continue({credentials: credentails});
        } else {
          return reply(Boom.unauthorized('Bad username or password', 'Basic'), null, { credentials: resp.credentials });
        }
      }).catch(function(err){
        return reply(err, null, {  });
      }).done();
    }
  };
};

exports.register = function(plugin, options, next){
  plugin.auth.scheme('who-dat', internals.implementation);
  next();
};

exports.register.attributes = {
  pkg: require('../package.json')
};