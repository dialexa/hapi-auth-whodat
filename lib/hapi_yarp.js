'use strict';

var Boom = require('boom');
var yarp = require('yarp');

var onError = function(err) {
  if (err.statusCode && err.data) {
    throw new Boom(err.data.message, { statusCode: err.statusCode });
  } else {
    throw err;
  }
};

module.exports = function(options) {
  return yarp(options).catch(onError);
};
