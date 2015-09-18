'use strict';

var Boom = require('boom');
var yarp = require('yarp');

var onError = function(err) {
  if (err.statusCode && err.data) {
    throw Boom.create(err.statusCode, err.data.message);
  } else {
    throw err;
  }
};

module.exports = function(options) {
  return yarp(options).catch(onError);
};
