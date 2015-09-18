'use strict';

var Hapi = require('hapi');
var Joi = require('joi');
var Lab = require('lab');
var nock = require('nock');

var lab = exports.lab = Lab.script();
var beforeEach = lab.beforeEach;
var afterEach = lab.afterEach;
var describe = lab.experiment;
var it = lab.test;
var expect = require('code').expect;

var internals = {};

internals.header = function(username, password) {
  return 'Basic ' + (new Buffer(username + ':' + password, 'utf8')).toString('base64');
};

describe('Authentication', function() {
  var server;

  beforeEach(function(done) {
    server = new Hapi.Server({ debug: { log: [ 'error' ], request: [ 'error' ] } }).connection({ host: 'test' });
    done();
  });

  it('should verify credentials with an external server with internal authentication with POST', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server with internal authentication with GET', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .get('/credentials?app=foo&username=other_user&password=shhhhh')
                .reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials?app=foo',
        method: 'GET',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server without internal authentication with GET', function(done) {
    var post = nock('https://my.app.com')
                .get('/credentials?app=foo&username=other_user&password=shhhhh')
                .reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials?app=foo',
        method: 'GET'
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server with a differnt object name for POST', function(done) {
    var post = nock('https://my.app.com')
                .post('/credentials', {
                  foo: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        objectName: 'foo'
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server without an object name', function(done) {
    var post = nock('https://my.app.com')
      .post('/credentials', { username: 'other_user', password: 'shhhhh' })
      .reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        objectName: null
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server with custom username/password properties in GET', function(done) {
    var post = nock('https://my.app.com')
                .get('/credentials?user_id=other_user&secretword=shhhhh')
                .reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        usernameProperty: 'user_id',
        passwordProperty: 'secretword'
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server with custom username/password properties in POST', function(done) {
    var post = nock('https://my.app.com')
            .post('/credentials', {
              user_id: 'other_user', secretword: 'shhhhh'
            }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        objectName: null,
        usernameProperty: 'user_id',
        passwordProperty: 'secretword'
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });
});

describe('Pre-auth', function() {
  var server;

  beforeEach(function(done) {
    server = new Hapi.Server().connection({ host: 'test' });
    done();
  });

  afterEach(function(done) {
    nock.cleanAll();
    done();
  });

  it('should not accept an unauthenticated request', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test'
      }, function(res) {
        expect(res.statusCode).to.equal(401);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a password', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', '') }
      }, function(res) {
        expect(res.statusCode).to.equal(401);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a username', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('', 'password') }
      }, function(res) {
        expect(res.statusCode).to.equal(401);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a valid auth header', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'Foo' }
      }, function(res) {
        expect(res.statusCode).to.equal(400);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a valid auth header', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'Basic Bar' }
      }, function(res) {
        expect(res.statusCode).to.equal(400);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a valid auth header', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'NotBasic Bar' }
      }, function(res) {
        expect(res.statusCode).to.equal(400);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a valid auth header', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'Basic Bar Bar' }
      }, function(res) {
        expect(res.statusCode).to.equal(400);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });
});

describe('Bad Authentication', function() {
  var server;

  beforeEach(function(done) {
    server = new Hapi.Server().connection({ host: 'test' });
    done();
  });

  afterEach(function(done) {
    nock.cleanAll();
    done();
  });

  it('should fail on credentials that fail authentication with an external server', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, { credentials: { result: 'failed' } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(401);
        post.done();
        done();
      });
    });
  });

  it('should fail on good credentials when the auth creds fail basic auth with an external server', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(401, { credentials: { result: 'failed' } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(401);
        post.done();
        done();
      });
    });
  });

  it('should use external error message if returned', function(done) {
    var reqError = {
      error: 'Bad Request',
      message: 'child "appId" fails because ["appId" with value " ba244680-8910-4a40-9e52-0f11069fda69" fails to match the required pattern: /^(([a-f\\d]{8}(-[a-f\\d]{4}){3}-[a-f\\d]{12}?)|_internal)$/]',
      statusCode: 400,
      validation: { keys: [ 'name' ], source: 'params' }
    };

    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
      .post('/credentials', {
        credentials: { username: 'other_user', password: 'shhhhh' }
      }).reply(400, reqError);

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(reqError.statusCode);
        expect(res.result.message).to.equal(reqError.message);
        post.done();
        done();
      });
    });
  });

  it('should throw 500 on server error', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
      .post('/credentials', {
        credentials: { username: 'other_user', password: 'shhhhh' }
      }).replyWithError('it failed horribly');

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(500);
        post.done();
        done();
      });
    });
  });
});

describe('Credentials object', function() {
  var server;

  beforeEach(function(done) {
    server = new Hapi.Server().connection({ host: 'test' });
    done();
  });

  afterEach(function(done) {
    nock.cleanAll();
    done();
  });

  it('should fill in credentials object with data from the external server', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .get('/credentials?username=other_user&password=shhhhh')
                .reply(200, { credentials: { authenticated: true, name: 'frank' } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          expect(req.auth.credentials).to.be.an.object();
          expect(req.auth.credentials.id).to.equal('other_user');
          expect(req.auth.credentials.name).to.equal('frank');
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should accept a credentials object with no object name', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .get('/credentials?username=other_user&password=shhhhh')
                .reply(200, { authenticated: true, name: 'frank' });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        auth: {
          username: 'me',
          password: 'secret'
        },
        responseObjectName: null
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          expect(req.auth.credentials).to.be.an.object();
          expect(req.auth.credentials.id).to.equal('other_user');
          expect(req.auth.credentials.name).to.equal('frank');
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });
});

describe('Bearer token auth', function() {
  var server;

  beforeEach(function(done) {
    server = new Hapi.Server({ debug: { log: [ 'error' ], request: [ 'error' ] } });
    server.connection({ host: '127.0.0.1' });
    done();
  });

  afterEach(function(done) {
    nock.cleanAll();
    done();
  });

  it('should accept a bearer token', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { token: 'asdfasdf' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'Bearer asdfasdf' }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should add the id from the credentials response', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { token: 'asdfasdf' }
                }).reply(200, { credentials: { authenticated: true, id: 'other_user' } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          expect(req.auth.credentials.id).to.equal('other_user');
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'Bearer asdfasdf' }
      }, function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should use the cache if provided as an option', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
      .post('/credentials', { credentials: { token: 'asdfasdf' } })
      .reply(200, { credentials: { authenticated: true, id: 'other_user' } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        },
        cache: {
          expiresIn: 20 * 1000,
          segment: 'whodat'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        handler: function(req, reply) {
          expect(req.auth.credentials.id).to.equal('other_user');
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.start(function(startErr) {
        expect(startErr).to.not.exist();

        server.inject({
          method: 'GET',
          url: '/test',
          headers: { authorization: 'Bearer asdfasdf' }
        }, function(res) {
          expect(res.statusCode).to.equal(200);
          post.done();

          // second request should use cache and not need nock
          server.inject({
            method: 'GET',
            url: '/test',
            headers: { authorization: 'Bearer asdfasdf' }
          }, function(res2) {
            expect(res2.statusCode).to.equal(200);

            server.stop(done);
          });
        });
      });
    });
  });
});

describe('Query Param auth', function() {
  var server;

  beforeEach(function(done) {
    server = new Hapi.Server({ debug: { log: [ 'error' ], request: [ 'error' ] } });
    server.connection({ host: '127.0.0.1' });
    done();
  });

  afterEach(function(done) {
    nock.cleanAll();
    done();
  });

  it('should take an option to set token query param name', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { token: 'asdfasdf' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        },
        queryTokenName: 'access_token'
      });

      server.route({
        method: 'GET',
        path: '/test',
        config: { validate: { query: Joi.object() } },
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject('/test?access_token=asdfasdf', function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should default token query param name to token', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { token: 'asdfasdf' }
                }).reply(200, { credentials: { authenticated: true } });

    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        }
      });

      server.route({
        method: 'GET',
        path: '/test',
        config: { validate: { query: Joi.object() } },
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject('/test?token=asdfasdf', function(res) {
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should take an option to turn off token as query param', function(done) {
    server.register(require('../'), function(err) {
      expect(err).to.not.exist();
      server.auth.strategy('default', 'whodat', 'required', {
        url: 'https://my.app.com/credentials',
        method: 'POST',
        auth: {
          username: 'me',
          password: 'secret'
        },
        allowQueryToken: false
      });

      server.route({
        method: 'GET',
        path: '/test',
        config: { validate: { query: Joi.object() } },
        handler: function(req, reply) {
          reply({ foo: 'bar' }).code(200);
        }
      });

      server.inject('/test?token=asdfasdf', function(res) {
        expect(res.statusCode).to.equal(401);
        done();
      });
    });
  });
});
