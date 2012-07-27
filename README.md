## Facebook nodejs
A simple module for querying Facebook graph api and fql

## Usage example

	express = require('express');
	fbgraph = require('fbgraph');
	app = express.createServer();
	app.use(fbgraph.auth({appId : "...",
		appSecret : "...",
		redirectUri : "..."}));
		
	app.get('/', function(req, res) {
		req.facebook.graph('/me', function(err, me) {
			console.log(me);
		});
	});
