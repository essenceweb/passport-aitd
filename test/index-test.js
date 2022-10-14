var vows = require('vows');
var assert = require('assert');
var aitd = require('passport-aitd');


vows.describe('passport-aitd').addBatch({
  
  'module': {
    'should report a version': function (x) {
      assert.isString(aitd.version);
    },
  },
  
}).export(module);
