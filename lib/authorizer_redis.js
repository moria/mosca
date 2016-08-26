/*
	this is a authorizer for mosca with auth data in redis
	the redis key-value pair is like bellow

 */

"use strict";

var Redis = require("ioredis");
var hasher = require("pbkdf2-password")();
var Qlobber = require('qlobber').Qlobber;

function AuthorizerRedis(redisOptions) {
  this.acls = {};
  this.redisOptions = redisOptions || {};
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
    var aclInfo = that.acls[client.user];
    var matcher = new Qlobber({separator:"/",wildcard_one:"+",wildcard_some:"#"});
    for (var i = 0; i < aclInfo.length; ++i) {
      if (aclInfo[i].access && (parseInt(aclInfo[i].access) === 2) || parseInt(aclInfo[i].access) === 3) {
          matcher.add(aclInfo[i].topic, i);
      }
    }
    var matches = matcher.match(topic);
    if (matches.length) {
      cb(null, true);
    } else {
      cb(null, false);
    }
  };
});

/**
 * It returns the authorizeSubscribe function to plug into mosca.Server.
 *
 * @api public
 */
AuthorizerRedis.prototype.__defineGetter__("authorizeSubscribe", function() {
  var that = this;
  return function(client, topic, payload, cb) {
    var aclInfo = that.acls[client.user];
    var matcher = new Qlobber({separator:"/",wildcard_one:"+",wildcard_some:"#"});
    for (var i = 0; i < aclInfo.length; ++i) {
      if (aclInfo[i].access && (parseInt(aclInfo[i].access) === 1 || parseInt(aclInfo[i].access) === 3)) {
          matcher.add(aclInfo[i].topic, i);
      }
    }
    var matches = matcher.match(topic);
    if (matches.length) {
      cb(null, true);
    } else {
      cb(null, false);
    }
  };
});

/**
 * build redis client according to the option
 * @return {redis connection object} [description]
 */
AuthorizerRedis.prototype._buildClient = function() {
  var options = this.redisOptions || {};

  if (this.redisClient) {
    return this.redisClient;
  }

  if (this.redisOptions.host) {
    options.host = this.redisOptions.host;
  }

  if (this.redisOptions.port) {
    options.port = this.redisOptions.port;
  }

  if (this.redisOptions.db) {
    options.db = this.redisOptions.db;
  }

  if (this.redisOptions.password) {
    options.password = this.redisOptions.password;
  }

  return new Redis(options);
};

/**
 * [_authenticate description]
 * @param  {[type]}   client [description]
 * @param  {[type]}   user   [description]
 * @param  {[type]}   pass   [description]
 * @param  {Function} cb     [description]
 * @return {[type]}          [description]
 */
AuthorizerRedis.prototype._authenticate = function(client, user, pass, cb) {
  var missingUser = !user || !pass;
  if (missingUser) {
    cb(null, false);
    return;
  }
  // when connect get auth and acl info anyway
  this._checkPassAndGetACL(client, user, pass, function(err, result) {
    cb(err, result);
  });
};

/**
 * [_checkPassAndGetACL description]
 * @param  {object}     client   客户端对象
 * @param  {string}     user     [用户名]
 * @param  {[string]}   pass     [密码]
 * @param  {Function}   cb       [description]
 * @return {[type]}              [description]
 */
AuthorizerRedis.prototype._checkPassAndGetACL = function(client, user, pass, cb) {
  var authkey = 'user:auth:' + user;
  var aclkey = 'user:acl:' + user;
  //get from redis
  this.redisClient = this._buildClient();
  this.redisClient.pipeline([
    ['get', authkey],
    ['get', aclkey]
  ]).exec(function(err, result) {
    if (!result[0][0]) {
      var userInfo = {};
      try {
        userInfo = JSON.parse(result[0][1]);
      } catch (e) {
        client.logger.warn('parse user auth info ' + result[0][1] + ' to json error ' + e.message);
        cb(null, false);
        return;
      }
      if (!userInfo) {
        cb(null, false);
        return;
      }
      var salt = userInfo.salt;
      hasher({
        password: pass.toString(),
        salt: salt
      }, function(err, pass, salt, hash) {
        if (err) {
          client.logger.info('user:'+user+';pass:'+pass+';hash:'+hash+';salt:'+salt+';no pass');
          cb(err);
          return;
        }
        var success = (userInfo.password === hash);
        if (success) {
          client.user = user;
          // restore user acl 
          var aclInfo = {};
          try {
            aclInfo = JSON.parse(result[1][1]);
          } catch (e) {
            client.logger.warn('parse user acl info ' + result[1][1] + ' to json error ' +  + e.message);
            aclInfo = {};
          }
          this.acls[user] = aclInfo;
        }
        cb(null, success);
      });
    } else {
      client.logger.warn('get user auth key ' + authkey + ' return ' + result[0][0]);
      cb(null, false);
    }
  });
}

