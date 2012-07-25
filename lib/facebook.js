var https = require('https');
var url = require('url');
var crypto = require('crypto');

var DOMAIN_MAP = {
	api : 'https://api.facebook.com/',
	apiVideo : 'https://api-video.facebook.com/',
	apiRead : 'https://api-read.facebook.com/',
	graph : 'https://graph.facebook.com/',
	graphVideo : 'https://graph-video.facebook.com/',
	www : 'https://www.facebook.com/',
};

var appId;
var appSecret;
var user;
var signedRequest;
var state;
var accessToken;

