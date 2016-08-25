/*
	this is a authorizer for mosca with auth data in redis
	the redis key-value pair is like bellow

 */

"use strict";

var Redis = require("ioredis");
var hasher = require("pbkdf2-password")();
var minimatch = require("minimatch");
var defaultGlob = "**";

function AuthorizerRedis(redisOptions, users) {
  this.users = users || {};
  this.options.redisOptions = redisOptions || {};
  this.redisClient = null;
}
module.exports = AuthorizerRedis;

/**
 * It returns the authenticate function to plug into mosca.Server.
 *
 * @api public
 */
AuthorizerRedis.prototype.__defineGetter__("authenticate", function() {
  var that = this;
  return function(client, user, pass, cb) {
    that._authenticate(client, user, pass, cb);
  };
});

/**
 * It returns the authorizePublish function to plug into mosca.Server.
 *
 * @api public
 */
AuthorizerRedis.prototype.__defineGetter__("authorizePublish", function() {
  var that = this;
  return function(client, topic, payload, cb) {
    cb(null, minimatch(topic, that.users[client.user].authorizePublish || defaultGlob));
  };
});

/**
 * It returns the authorizeSubscribe function to plug into mosca.Server.
 *
 * @api public
 */
AuthorizerRedis.prototype.__defineGetter__("authorizeSubscribe", function() {
  var that = this;
  return function(client, topic, cb) {
    cb(null, minimatch(topic, that.users[client.user].authorizeSubscribe || defaultGlob));
  };
});

/**
 * build redis client according to the option
 * @return {redis connection object} [description]
 */
AuthorizerRedis.prototype._buildClient = function() {
  var options = this.options.redisOptions || {};

  if (this.redisClient) {
    return this.redisClient;
  }

  if (this.options.host) {
    options.host = this.options.host;
  }

  if (this.options.port) {
    options.port = this.options.port;
  }

  if (this.options.db) {
    options.db = this.options.db;
  }

  if (this.options.password) {
    options.password = this.options.password;
  }

  return new Redis(options);
};

/**
 * The real authentication function
 *
 * @api private
 */
AuthorizerRedis.prototype._authenticate = function(client, user, pass, cb) {

  var missingUser = !user || !pass;

  if (missingUser) {
    cb(null, false);
    return;
  }

  if (!this.users[user]) {

  } else {
    this._checkPass(client, user, pass, userInfo, cb, function(err, result) {
      this._getUserAuthInfo(user, cb, function(err, authInfo) {

      });
    });
  }
};

AuthorizerRedis.prototype._checkPassAndGetACL = function(client, user, pass, userInfo, cb) {
  var authkey = 'user:' + user;
  var aclkey = 'user:acl:' + user;
  //get from redis
  this.redisClient = this._buildClient();
  this.redisClient.pipline([
    ['get', key],
    ['get', aclkey]
  ]).exec(function(err, result) {
    if (!result[0][0]) {
      
    } else {
      cb(null, false);
    }
  });

  this.redisClient.get(key, function(err, userInfo){
    if( !err && userInfo ) {
      userInfo = JSON.parse(userInfo);
      this._checkPass(client, user, pass, userInfo, cb, function(err, result) {
        this._getUserAuthInfo(user, cb, function(err, authInfo) {

        });
      });
    } else {
      cb(null, false);
    }
  });

  var salt = userInfo.salt;
  hasher({
    password: pass.toString(),
    salt: salt
  }, function(err, pass, salt, hash) {
    if (err) {
      cb(err);
      return;
    }
    var success = (userInfo.password === hash);
    if (success) {
      client.user = user;
      this.users[user] = user;
    }
    cb(null, success);
  });
}

/**
 * An utility function to add an user.
 *
 * @api public
 * @param {String} user The username
 * @param {String} pass The password
 * @param {String} authorizePublish The authorizePublish pattern
 *   (optional)
 * @param {String} authorizeSubscribe The authorizeSubscribe pattern
 *   (optional)
 * @param {Function} cb The callback that will be called after the
 *   insertion.
 */
Authorizer.prototype.addUser = function(user, pass, authorizePublish,
                                        authorizeSubscribe, cb) {
  var that = this;

  if (typeof authorizePublish === "function") {
    cb = authorizePublish;
    authorizePublish = null;
    authorizeSubscribe = null;
  } else if (typeof authorizeSubscribe == "function") {
    cb = authorizeSubscribe;
    authorizeSubscribe = null;
  }

  if (!authorizePublish) {
    authorizePublish = defaultGlob;
  }

  if (!authorizeSubscribe) {
    authorizeSubscribe = defaultGlob;
  }

  hasher({
    password: pass.toString()
  }, function(err, pass, salt, hash) {
    if (!err) {
      that.users[user] = {
        salt: salt,
        hash: hash,
        authorizePublish: authorizePublish,
        authorizeSubscribe: authorizeSubscribe
      };
    }
    cb(err);
  });
  return this;
};


/**
 * An utility function to delete a user.
 *
 * @api public
 * @param {String} user The username
 * @param {String} pass The password
 * @param {Function} cb The callback that will be called after the
 *   deletion.
 */
Authorizer.prototype.rmUser = function(user, cb) {
  delete this.users[user];
  cb();
  return this;
};
