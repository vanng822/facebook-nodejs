## Facebook nodejs
A simple module for querying Facebook graph api and fql

## Usage example

	express = require('express');
	fbgraph = require('fbgraphapi');
	app = express.createServer();
	app.use(fbgraph.auth({appId : "...",
		appSecret : "...",
		redirectUri : "..."}));
		
	app.get('/', function(req, res) {
		/* See http://developers.facebook.com/docs/reference/api/ for more */
		req.facebook.graph('/me', function(err, me) {
			console.log(me);
		});
		
		req.facebook.graph('/me?fields=id,name', function(err, me) {
			console.log(me);
		});
		
		req.facebook.me(function(err, me) {
			console.log(me);
		});
		
		req.facebook.me(function(err, me) {
			console.log(me);
		}, 'id,name');
		
		
		/* Single fql query */
		req.facebook.fql('SELECT uid FROM user WHERE uid IN (SELECT uid2 FROM friend WHERE uid1=me())  AND is_app_user = 1', function(err, result) {
			console.log(result);
		});
		
		/* Multiple fql queries */
		req.facebook.fql({
			uids : 'SELECT uid FROM user WHERE uid IN (SELECT uid2 FROM friend WHERE uid1=me()) AND is_app_user = 1',
			myapp : 'SELECT application_id, role FROM developer WHERE developer_id = me()'
		}, function(err, result) {
			console.log(result);
		});
	});
