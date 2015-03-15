
var assert = require('assert');
var fbgraphapi = require('../index.js');

describe('Accessing public data', function(){
	describe('Calling .graph with /1155678417 without access_token with version v1.0', function(){
		it('should return public info about the author', function(done) {
			var fb = new fbgraphapi.Facebook(null, 'v1.0');
			fb.graph('/1155678417', function(err, res) {
				console.log(err)
				var expected = { id: '1155678417',
						  first_name: 'Van Nhu',
						  gender: 'male',
						  last_name: 'Nguyen',
						  locale: 'en_US',
						  name: 'Van Nhu Nguyen',
						  username: 'nguyen.van.nhu' };
				assert.deepEqual(res, expected);
				done();
			});
		});
	});
	
	describe('Calling .graph with /1155678417 without access_token with version v2.2', function(){
		it('should return "An access token is required to request this resource."', function(done) {
			var fb = new fbgraphapi.Facebook(null, 'v2.2');
			fb.graph('/1155678417', function(err, res) {
				expected = {
				  error_subcode: null,
				  type: 'OAuthException',
				  code: 104,
				  statusCode: 400,
				  message: 'An access token is required to request this resource.' }
				assert.deepEqual(err, expected);
				done();
			});
		});
	});
});
