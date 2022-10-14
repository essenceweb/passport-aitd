var vows = require('vows');
var assert = require('assert');
var util = require('util');
var AITDStrategy = require('passport-aitd/strategy');


vows.describe('AITDStrategy').addBatch({
  
  'strategy': {
    topic: function() {
      return new AITDStrategy({
        clientID: 'ABC123',
        clientSecret: 'secret'
      },
      function() {});
    },
    
    'should be named aitd': function (strategy) {
      assert.equal(strategy.name, 'aitd');
    },
  },
  
  'strategy with scopes': {
    topic: function() {
      return new AITDStrategy({
        clientID: 'ABC123',
        clientSecret: 'secret',
        scope: ['general']
      },
      function() {});
    },
    
    'should have correct scopes': function (strategy) {
      assert.deepEqual(strategy._scope, ['general']);
    },

    'should have space as a scope separator': function (strategy) {
      assert.equal(strategy._scopeSeparator, ' ');
    },
  },

  'strategy when loading user profile': {
    topic: function() {
      var strategy = new AITDStrategy({
        clientID: 'ABC123',
        clientSecret: 'secret',
        scope: ['general']
      },
      function() {});
      
      // mock
      strategy._oauth2.get = function(url, accessToken, callback) {
        if (url == 'https://aitd.com.au/rest/whoami') {
          var body = '{ "user": {  "mail": "m@m.com", "person_name": {"firstname":"firstname", "lastname": "lastname" } } }';
          callback(null, body, undefined);
        } else {
          callback(new Error('Incorrect user profile URL'));
        }
      }
      
      return strategy;
    },
    
    'when told to load user profile': {
      topic: function(strategy) {
        var self = this;
        function done(err, profile) {
          self.callback(err, profile);
        }
        
        process.nextTick(function () {
          strategy.userProfile('access-token', done);
        });
      },
      
      'should not error' : function(err, req) {
        assert.isNull(err);
      },
      'should load profile' : function(err, profile) {
        assert.equal(profile.provider, 'aitd');
        assert.equal(profile.email, 'm@m.com');
        assert.equal(profile.firstname, 'firstname');
        assert.equal(profile.lastname, 'lastname');
      },
      'should set raw property' : function(err, profile) {
        assert.isString(profile._raw);
      },
      'should set json property' : function(err, profile) {
        assert.isObject(profile._json);
      },
    },
  },

  'strategy when loading user profile and encountering an error': {
    topic: function() {
      var strategy = new AITDStrategy({
        clientID: 'ABC123',
        clientSecret: 'secret',
        scope: ['general']
      },
      function() {});
      
      // mock
      strategy._oauth2.get = function(url, accessToken, callback) {
        callback(new Error('something-went-wrong'));
      }
      
      return strategy;
    },
    
    'when told to load user profile': {
      topic: function(strategy) {
        var self = this;
        function done(err, profile) {
          self.callback(err, profile);
        }
        
        process.nextTick(function () {
          strategy.userProfile('access-token', done);
        });
      },
      
      'should error' : function(err, req) {
        assert.isNotNull(err);
      },
      'should wrap error in InternalOAuthError' : function(err, req) {
        assert.equal(err.constructor.name, 'InternalOAuthError');
      },
      'should not load profile' : function(err, profile) {
        assert.isUndefined(profile);
      },
    },
  },
}).export(module);
