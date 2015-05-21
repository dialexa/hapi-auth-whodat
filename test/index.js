var Lab = require('lab');
var Hapi = require('hapi');
var nock = require('nock');

var lab = exports.lab = Lab.script();
var before = lab.before;
var beforeEach = lab.beforeEach;
var afterEach = lab.afterEach;
var describe = lab.experiment;
var it = lab.test;
var expect = require('code').expect;

var internals = {};

internals.header = function (username, password) {
  return 'Basic ' + (new Buffer(username + ':' + password, 'utf8')).toString('base64');
};

describe('Authentication', function(){
  var server;

  beforeEach(function(done){
    server = new Hapi.Server({debug: {request: ['error']}}).connection({ host: 'test' });
    done();
  });

  afterEach(function(done){
    nock.cleanAll();
    done();
  });

  it('should verify credentials with an external server with internal authentication with POST', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res){
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server with internal authentication with GET', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .get('/credentials?app=foo&username=other_user&password=shhhhh')
                .reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res){
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server without internal authentication with GET', function(done){
    var post = nock('https://my.app.com')
                .get('/credentials?app=foo&username=other_user&password=shhhhh')
                .reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res){
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server with a differnt object name for POST', function(done){
    var post = nock('https://my.app.com')
                .post('/credentials', {
                  foo: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res){
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server without an object name', function(done){
        var post = nock('https://my.app.com')
                .post('/credentials', {
                  username: 'other_user', password: 'shhhhh'
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res){
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server with custom username/password properties in GET', function(done){
        var post = nock('https://my.app.com')
                .get('/credentials?user_id=other_user&secretword=shhhhh')
                .reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res){
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });

  it('should verify credentials with an external server with custom username/password properties in POST', function(done){
        var post = nock('https://my.app.com')
                .post('/credentials', {
                  user_id: 'other_user', secretword: 'shhhhh'
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res){
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });
});

describe('Pre-auth', function(){
  var server;

  beforeEach(function(done){
    server = new Hapi.Server().connection({ host: 'test' });
    done();
  });

  afterEach(function(done){
    nock.cleanAll();
    done();
  });

  it('should not accept an unauthenticated request', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test'
      }, function(res){
        expect(res.statusCode).to.equal(401);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a password', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', '') }
      }, function(res){
        expect(res.statusCode).to.equal(401);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a username', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('', 'password') }
      }, function(res){
        expect(res.statusCode).to.equal(401);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a valid auth header', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'Foo' }
      }, function(res){
        expect(res.statusCode).to.equal(400);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a valid auth header', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'Basic Bar' }
      }, function(res){
        expect(res.statusCode).to.equal(400);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a valid auth header', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'NotBasic Bar' }
      }, function(res){
        expect(res.statusCode).to.equal(400);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });

  it('should not accept a request without a valid auth header', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'Basic Bar Bar' }
      }, function(res){
        expect(res.statusCode).to.equal(400);
        expect(post.isDone()).to.be.false();
        done();
      });
    });
  });
});

describe('Bad Authentication', function(){
  var server;

  beforeEach(function(done){
    server = new Hapi.Server().connection({ host: 'test' });
    done();
  });

  afterEach(function(done){
    nock.cleanAll();
    done();
  });

  it('should fail on credentials that fail authentication with an external server', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(200, {credentials: { result: 'failed'}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res){
        expect(res.statusCode).to.equal(401);
        post.done();
        done();
      });
    });
  });

  it('should fail on good credentials when the auth creds fail basic auth with an external server', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { username: 'other_user', password: 'shhhhh' }
                }).reply(401, {credentials: { result: 'failed'}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res){
        expect(res.statusCode).to.equal(500);
        post.done();
        done();
      });
    });
  });
});

describe('Credentials object', function(){
  var server;

  beforeEach(function(done){
    server = new Hapi.Server({debug: {request: ['error']}}).connection({ host: 'test' });
    done();
  });

  afterEach(function(done){
    nock.cleanAll();
    done();
  });

  it('should fill in credentials object with data from the external server', function(done){
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .get('/credentials?username=other_user&password=shhhhh')
                .reply(200, {credentials: { authenticated: true, name: 'frank'}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: internals.header('other_user', 'shhhhh') }
      }, function(res){
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });
});

describe('Bearer token auth', function() {
  var server;

  beforeEach(function(done){
    server = new Hapi.Server({debug: {request: ['error']}}).connection({ host: 'test' });
    done();
  });

  afterEach(function(done){
    nock.cleanAll();
    done();
  });

  it('should accept a bearer token', function(done) {
    var post = nock('https://my.app.com').matchHeader('Authorization', 'Basic bWU6c2VjcmV0')
                .post('/credentials', {
                  credentials: { token: 'asdfasdf' }
                }).reply(200, {credentials: { authenticated: true}});

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
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'Bearer asdfasdf' }
      }, function(res){
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
                }).reply(200, {credentials: { authenticated: true, id: 'other_user'}});

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
          expect(req.auth.credentials.id).to.equal('other_user')
          reply({foo: 'bar'}).code(200);
        }
      });

      server.inject({
        method: 'GET',
        url: '/test',
        headers: { authorization: 'Bearer asdfasdf' }
      }, function(res){
        expect(res.statusCode).to.equal(200);
        post.done();
        done();
      });
    });
  });
})