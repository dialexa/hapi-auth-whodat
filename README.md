WhoDat Auth Plugin for Hapi
============================

[![NPM](https://nodei.co/npm/hapi-auth-whodat.png)](https://nodei.co/npm/hapi-auth-whodat/)

[![npm version](https://badge.fury.io/js/hapi-auth-whodat.svg)](http://badge.fury.io/js/hapi-auth-whodat)
[![Build Status](https://travis-ci.org/dialexa/hapi-auth-whodat.svg)](https://travis-ci.org/dialexa/hapi-auth-whodat)

A BasicAuth plugin that checks credentials with an external authority.  Works with Hapi version 8 or later.


```bash
npm install --save hapi-auth-whodat
```



```javascript
var Hapi = require('hapi');

var server = new Hapi.Server();
server.connection({
  host: 'localhost',
  port: 8000
});

server.register(require('../'), function(err) {
  server.auth.strategy('default', 'whodat', true, {
    url: 'https://auth.app.com/credentials',
    auth: {
      username: 'internal',
      password: 'secret'
    }
  });

  server.start();
});
```


The above will attempt to authenticate each route by calling the given URL with the users's credentials.  For instance, if a user with username `john` and password `shhhhh` requests a route in this server, the url `https://auth.app.com/credentials?username=john&password=shhhhh` will be called via HTTP `GET`.  If the credentials are valid, the external authority should respond with:


```json
{
  "credentials" : {
    "authenticated": true
  }
}
```

Whatever is returned in the `credentials` object (in addition to the username set as `id`) will be set in the `req.auth.credentials` object accessible from the route.

## Plugin Options
The following options are available when registering the plugin:
- _'url'_ (required) - the URL to call for authentication.
- _'method'_ - the HTTP method to use.  Defaults to "GET".
- _'auth'_ - authentication object that will be included with the request to the external authority.  This authenticates the server with the external authority.  Can be an object including `username` and `password` or `null` to not authenticate the request.  Defaults to "credentials".
- _'objectName'_ - (when using the POST method) the name of the object to be sent to the external authority.  Can be a string or `null` to put the properties at the root level.  Defaults to "credentials".
- _'responseObjectName'_ - the name of the object that will be returned by the external authority.  Defaults to "credentials".
- _'otherData'_ - static object to be merged with the credentials object being sent.  Defaults to `null`.
- _'usernameProperty'_ , _'passwordProperty'_ - names of the `username` and `password` properties sent to the server.  Defaults to "username" and "password".
