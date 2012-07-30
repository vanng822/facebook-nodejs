var https = require('https');
var url = require('url');
var crypto = require('crypto');

var PROTOCOL = 'https://';
var USER_AGENT = 'facebook-nodejs (+https://github.com/vanng822/facebook-nodejs)';
var FB_SESSION_KEY_PREFIX = 'fbsk_';
var FB_SR_COOKIE_PREFIX = 'fbsr_';

var DOMAIN_MAP = {
	/*api : 'api.facebook.com',
	 apiVideo : 'api-video.facebook.com',
	 apiRead : 'api-read.facebook.com',*/
	graph : 'graph.facebook.com',
	graphVideo : 'graph-video.facebook.com',
	www : 'www.facebook.com',
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
}
var redirectLoginForm = module.exports.redirectLoginForm = function(req, res) {
	var state = establishCSRFTokenState(req);
	var currentUrl = getCurrentUrl(req);
	var query = '/dialog/oauth?client_id=' + appId + '&redirect_uri=' + currentUrl + '&scope=' + scope + '&state=' + state;
	var url = PROTOCOL + DOMAIN_MAP.www + query;
	redirect(res, url);
}
function authenticate(req, res, next) {
	var code, state, signedRequest, accessToken, expires;

	parseQuery(req);
	signedRequest = getSignedRequest(req);
	if(signedRequest && signedRequest.oauth_token) {
		setPersistentData(req, 'access_token', signedRequest.oauth_token);
		setPersistentData(req, 'expires', signedRequest.expires);
		setPersistentData(req, 'user_id', signedRequest.user_id);
		req.facebook = new Facebook(signedRequest.oauth_token);
		next();
		return;
	}
	accessToken = getPersistentData(req, 'access_token');
	expires = getPersistentData(req, 'expires');
	if(accessToken && expires && validateExpires(req, expires)) {
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

	redirect(res, redirectUri);
}

var Facebook = module.exports.Facebook = function(accessToken) {
	this._accessToken = null;
	if(accessToken) {
		this._setAccessToken(accessToken);
	}
}

Facebook.prototype = {
	_setAccessToken : function(accessToken) {
		this._accessToken = accessToken;
	},
	_getAccessToken : function() {
		return this._accessToken;
	},
	_graph : function(options, callback) {
		https.get(options, function(res) {
			var data = '';
			res.on('data', function(chunk) {
				data += chunk;
			});
			res.on('end', function() {
				try {
					if(res.statusCode == 200) {
						callback(null, JSON.parse(data));
					} else {
						/* just dump what we get */
						callback(new Error(data), null);
					}
				} catch(e) {/* json parse may throw error */
					callback(e, null);
				}
			});
		});
	},
	graph : function(path, callback) {
		if(path.indexOf('?') != -1) {
			if(path[path.length - 1] != '?' && path[path.length - 1] != '&') {
				path += '&';
			}
		} else {
			path += '?';
		}
		var options = {
			host : DOMAIN_MAP.graph,
			path : path + 'access_token=' + this._getAccessToken(),
			headers : {
				'User-Agent' : USER_AGENT
			}
		};
		this._graph(options, callback);
	},
	fql : function(query, callback) {
		var encodedQuery;
		if( query instanceof Object) {
			encodedQuery = encodeURIComponent(JSON.stringify(query));
		} else {
			encodedQuery = encodeURIComponent(query);
		}
		var options = {
			host : DOMAIN_MAP.graph,
			path : '/fql?q=' + encodedQuery + '&format=json&access_token=' + this._getAccessToken(),
			headers : {
				'User-Agent' : USER_AGENT
			}
		};
		this._graph(options, callback);
	},
	me : function(callback, fields) {
		var meUrl = '/me' + (fields? '?fields=' + fields : '');
		this.graph(meUrl, callback);
	}
	/* TODO: add some convenient methods for graph api */
}

/* TODO: use case or remove this */
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

}

function getAccessTokenFromCode(req, res, code, callback) {
	var query = '/oauth/access_token?client_id=' + appId + '&redirect_uri=' + getCurrentUrl(req) + '&client_secret=' + appSecret + '&code=' + code;
	var options = {
		host : DOMAIN_MAP.graph,
		path : query,
		headers : {
			'User-Agent' : USER_AGENT
		}
	};

	https.get(options, function(r) {
		var data = "";
		r.on('data', function(chunk) {
			data += chunk;
		});
		r.on('end', function() {
			if(r.statusCode == 200) {
				try {
					parsedUrl = url.parse('http://fakedomain.test?' + data, true);
					/* expires is relative so adding from now */
					callback(null, parsedUrl.access_token, math.floor(Date.now() / 1000) + parsedUrl.expires);
				} catch(e) {
					callback(e, null, null);
				}
			} else {
				callback(new Error('Can not get access_token. Data: ' + data), null, null);
			}
		});
	});
}

/* TODO: need to handle current url somehow to avoid data lost */
function getCurrentUrl(req) {
	return encodeURIComponent(redirectUri);
}

function redirect(res, url) {
	res.end('<script type="text/javascript">top.location.href="' + url + '"</script>');
}

function parseSignedRequest(signedRequest) {
	var sig, data, expectedSig;
	payload = signedRequest.split('.');
	sig = payload[0];
	try {
		data = JSON.parse(new Buffer(payload[1], 'base64').toString());
	} catch(e) {
		return null;
	}
	if(data.algorithm.toUpperCase() !== 'HMAC-SHA256') {
		console.log('Unknown signed_request hash algorithm: ' + data.algorithm + '. Expected HMAC-SHA256');
		return null;
	}
	expectedSig = crypto.createHmac('sha256', appSecret);
	expectedSig.update(payload[1]);
	expectedSig = expectedSig.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

	if(sig !== expectedSig) {
		console.log('Bad signed_request encoding. Expected: ' + expectedSig + ' but got: ' + sig);
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
	setPersistentData(req, 'state', state);
	return state;
}

function setPersistentData(req, key, value) {
	if(SUPPORT_KEYS.indexOf(key) == -1) {
		throw new Error('Does not support key: ' + key);
	}
	req.session[getSessionKey(key)] = value;
}

function getPersistentData(req, key, defaultValue) {
	if(SUPPORT_KEYS.indexOf(key) == -1) {
		throw new Error('Does not support key: ' + key);
	}
	defaultValue = (defaultValue == undefined) ? null : defaultValue;
	key = getSessionKey(key);
	return req.session.hasOwnProperty(key) ? req.session[key] : defaultValue;
}

function clearPersistentData(req, key) {
	if(SUPPORT_KEYS.indexOf(key) == -1) {
		throw new Error('Does not support key: ' + key);
	}
	delete req.session[getSessionKey(key)];
}

function clearAllPersistentData(req) {
	SUPPORT_KEYS.forEach(function(key) {
		delete req.session[getSessionKey(key)];
	});
}

function getSessionKey(key) {
	return FB_SESSION_KEY_PREFIX + key;
}

function parseQuery(req) {
	if(req.query === undefined) {
		req.query = url.parse(req.url, true).query || {};
	}
}

function getSignedRequestCookieName() {
	return FB_SR_COOKIE_PREFIX + appId;
}