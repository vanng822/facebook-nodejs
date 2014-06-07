
var assert = require('assert');
var fbgraphapi = require('../index.js');

describe('Accessing public data', function(){
	describe('Calling .graph with /zuck without access_token', function(){
		it('should return public info about Mark Zuckerberg', function(done) {
			var fb = new fbgraphapi.Facebook(null);
			fb.graph('/zuck', function(err, res) {
				expected = { id: '4',
						  first_name: 'Mark',
						  gender: 'male',
						  last_name: 'Zuckerberg',
						  link: 'https://www.facebook.com/zuck',
						  locale: 'en_US',
						  name: 'Mark Zuckerberg',
						  username: 'zuck' };
				assert.deepEqual(res, expected);
				done();
			});
		});
	});
});
