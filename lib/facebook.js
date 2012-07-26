var https = require('https');
var url = require('url');
var crypto = require('crypto');

var DOMAIN_MAP = {
	api : 'https://api.facebook.com/',
	apiVideo : 'https://api-video.facebook.com/',
	apiRead : 'https://api-read.facebook.com/',
	graph : 'graph.facebook.com',
	graphVideo : 'https://graph-video.facebook.com/',
	www : 'https://www.facebook.com/',
};

var DROP_QUERY_PARAMS = ['code', 'state', 'signed_request'];
var SUPPORT_KEYS = ['state', 'code', 'access_token', 'user_id', 'expires'];

var appId;
var appSecret;
var scope = '';
var redirectUri;

module.exports.auth = function(config) {
	if(!config || !config.appId || !config.appSecret || !config.redirectUri) {
		throw new Error('appId, appSecret or redirectUri is missing!');
	}
	appId = config.appId;
	appSecret = config.appSecret;
	redirectUri = config.redirectUri;

	if(config.scope) {
		scope = config.scope;
	}

	return authenticate;
};

function authenticate(req, res, next) {
	var error, code, state, signedRequest, accessToken, expires;

	parseQuery(req);
	
	signedRequest = getSignedRequest(req);
	if(signedRequest && signedRequest.oauth_token) {
		setPersistentData(req, 'access_token', signedRequest.oauth_token);
		setPersistentData(req, 'expires', signedRequest.expires);
		req.facebook = new Facebook(signedRequest.oauth_token);
		next();
		return;
	}
	
	accessToken = getPersistentData(req, 'access_token');
	expires = getPersistentData(req, 'expires', Math.floor(Date.now() / 1000));
	if(accessToken && validateExpires(req, expires)) {
		req.facebook = new Facebook(accessToken);
		next();
		return;
	}
	
	code = req.query.code;
	state = req.query.state;

	if(code && state && state === getPersistentData(req, 'state')) {
		getAccessTokenFromCode(req, res, code, function(err, accessToken, expires) {
			if(accessToken) {
				//setPersistentData(req, 'code', code);
				setPersistentData(req, 'access_token', accessToken);
				setPersistentData(req, 'expires', expires);
				req.facebook = new Facebook(accessToken);
			}
			next();
		});
		return;
	}
	error = req.query.error;
	if(error) {
		var errorObj = new Error(decodeURI(req.query.error_description));
		errorObj.error_reason = req.query.error_reason;
		errorObj.error_name = error;
		next(errorObj);
		return;
	}

	redirect(res, redirectUri);
};

function getUserAccessToken(req, res, callback) {
	var signedRequest = getSignedRequest(req);
	var accessToken, code;
	if(signedRequest) {
		if(signedRequest.hasOwnProperty('oauth_token')) {
			accessToken = signedRequest.oauth_token;
			setPersistentData(req, 'access_token', accessToken);
			callback(err, accessToken);
			return;
		}

		if(signedRequest.hasOwnProperty('code')) {
			code = signedRequest.code;
			getAccessTokenFromCode(req, res, code, function(err, accessToken, expires) {
				if(accessToken) {
					setPersistentData(req, 'code', code);
					setPersistentData(req, 'access_token', accessToken);
					setPersistentData(req, 'expires', expires);
				}
				callback(err, accessToken);
			});
			return;
		}
	}

	callback(null, getPersistentData(req, 'access_token'));

};

function getAccessTokenFromCode(req, res, code, callback) {
	var query = '/oauth/access_token?client_id=' + appId + '&redirect_uri=' + getCurrentUrl(req) + '&client_secret=' + appSecret + '&code=' + code;
	var opts = {
		host : DOMAIN_MAP.graph,
		path : query
	};

	console.log(opts);
	https.get(opts, function(r) {
		var data = "";
		r.on('data', function(chunk) {
			data += chunk;
		});
		r.on('end', function() {
			if(r.statusCode == 200) {
				parsedUrl = url.parse('http://fakedomain.test?' + data, true);
				/* expires is relative so adding from now */
				callback(null, parsedUrl.access_token, math.floor(Date.now() / 1000) + parsedUrl.expires);
			} else {
				/* TODO: determine error */
				callback(new Error('Can not get access_token'), null, null);
			}
		});
	});
}

var redirectLoginForm = module.exports.redirectLoginForm = function(req, res) {
	var state = establishCSRFTokenState(req);
	req.session.state = state;
	var currentUrl = getCurrentUrl(req);
	var query = 'dialog/oauth?client_id=' + appId + '&redirect_uri=' + currentUrl + '&scope=' + scope + '&state=' + state;
	var url = DOMAIN_MAP.www + query;
	redirect(res, url);
}

/* TODO: need to handle current url somehow to avoid data lost */
function getCurrentUrl(req) {
	return encodeURIComponent(redirectUri);
}

function redirect(res, url) {
	res.end('<script>top.location.href=\"' + url + '\"</script>');
}

function parseSignedRequest(signedRequest) {
	var sig, data, expectedSig;
	payload = signedRequest.split('.');
	sig = payload[0];
	data = JSON.parse(new Buffer(payload[1], 'base64').toString());

	if(data.algorithm.toUpperCase() !== 'HMAC-SHA256') {
		console.log('Unknown signed_request hash algorithm: ' + data.algorithm + '. Expected HMAC-SHA256');
		return null;
	}
	expectedSig = crypto.createHmac('sha256', appSecret);
	expectedSig.update(payload[1]);
	expectedSig = expectedSig.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

	if(sig !== expectedSig) {
		console.log('Bad signed_request encoding. Expected: ' + expectedSig + 'but got: ' + sig);
		return null;
	}

	return data;
}

function getSignedRequest(req) {
	var signedRequest;
	if(!req.hasOwnProperty('signedRequest')) {
		if(req.body !== undefined && req.body.hasOwnProperty('signed_request')) {
			signedRequest = parseSignedRequest(req.body.signed_request);
		} else if(req.cookies && req.cookies.hasOwnProperty(getSignedRequestCookieName())) {
			signedRequest = parseSignedRequest(req.cookies[getSignedRequestCookieName()]);
		}
		/* check expires */
		if(signedRequest && !validateExpires(req, signedRequest.expires)) {
			signedRequest = null;
		}
		/* keep it for this request only */
		req.signedRequest = signedRequest;
	}
	return req.signedRequest;
}

/* if expired clear all persistent data */
function validateExpires(req, expires) {
	if(!expires) {
		return false;
	}
	if(Date.now() - (expires * 1000) > 0) {
		clearAllPersistentData(req);
		return false;
	}
	return true;
}

function establishCSRFTokenState(req) {
	var shasum = crypto.createHash('md5'), state;
	shasum.update((Math.random() * (new Date().getTime())).toString());
	state = shasum.digest('hex');
	req.session.state = state;
	return state;
}

function setPersistentData(req, key, value) {
	if(SUPPORT_KEYS.indexOf(key) == -1) {
		throw new Error('Does not support key:' + key);
	}
	req.session[key] = value;
}

function getPersistentData(req, key, defaultValue) {
	if(SUPPORT_KEYS.indexOf(key) == -1) {
		throw new Error('Does not support key:' + key);
	}
	defaultValue = (defaultValue == undefined) ? null : defaultValue;

	return req.session.hasOwnProperty(key) ? req.session[key] : defaultValue;
}

function clearPersistentData(req, key) {
	if(SUPPORT_KEYS.indexOf(key) == -1) {
		throw new Error('Does not support key:' + key);
	}
	delete req.session[key];
}

function clearAllPersistentData(req) {
	SUPPORT_KEYS.forEach(function(key) {
		delete req.session[key];
	});
}

function parseQuery(req) {
	if(req.query === undefined) {
		req.query = url.parse(req.url, true).query || {};
	}
}

function getSignedRequestCookieName() {
	return 'fbsr_' + appId;
}

var Facebook = function(accessToken) {
	this.accessToken;
	if(accessToken) {
		this.setAccessToken(accessToken);
	}
}

Facebook.prototype = {
	setAccessToken : function(accessToken) {
		this.accessToken = accessToken;
	},
	getAccessToken : function() {
		return this.accessToken;
	},
	_graph : function(opts, callback) {
		https.get(opts, function(res) {
			var data = "";
			res.on('data', function(chunk) {
				data += chunk;
			});
			res.on('end', function() {/* TODO: error handling */
				callback(null, JSON.parse(data));
			});
		});
	},
	graph : function(path, method, params, callback) {/* just get for now */
		var opts = {
			host : DOMAIN_MAP.graph,
			path : path + '&access_token=' + this.accessToken
		};
		this._graph(opts, callback);
	},
	fql : function(query, callback) {

	}
}