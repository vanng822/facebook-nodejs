var version = require('../package.json').version;
var https = require('https');
var url = require('url');
var crypto = require('crypto');
var util = require('util');
var querystring = require('querystring');

var PROTOCOL = 'https://';
var USER_AGENT = 'facebook-nodejs/' + version + ' (+https://github.com/vanng822/facebook-nodejs)';
/**
 * Prefix to avoid name collision in session and cookies
 */
var FB_SESSION_KEY_PREFIX = 'fbsk_';
var FB_SR_COOKIE_PREFIX = 'fbsr_';

var DEFAULT_USER_FIELDS = 'uid, name';

/**
 * For different request
 * www is for login dialog
 *
 */
var DOMAIN_MAP = {
	graph : 'graph.facebook.com',
	graphVideo : 'graph-video.facebook.com',
	www : 'www.facebook.com',
};

var DROP_QUERY_PARAMS = ['code', 'state', 'signed_request'];
/* allowing persistence */
var SUPPORT_KEYS = ['state', 'code', 'access_token', 'user_id', 'expires'];

/* Application configurations */
var appId;
var appSecret;
var scope = '';
var redirectUri;
var apiVersion = '';
/* data only store when user a redirect for login and no clean up until next login */
/* application which uses this data should have that responsibility */
/** Data:
 * 	{
 * 		body: req.body,
 *		params: req.params,
 *		query: req.query,
 *		files: req.files
 * }
 */
var REQUEST_DATA_SESSION_KEY = module.exports.REQUEST_DATA_SESSION_KEY = 'facebook.nodejs.requestData';
/* not run auth on those */
var skipUrlPatterns = null;

module.exports.auth = function(config) {
	var i;
	if(!config || !config.appId || !config.appSecret || !config.redirectUri) {
		throw new Error('appId, appSecret or redirectUri is missing!');
	}
	appId = config.appId;
	appSecret = config.appSecret;
	redirectUri = config.redirectUri;

	if(config.scope) {
		scope = config.scope;
	}
	
	if (config.apiVersion) {
		apiVersion = String(config.apiVersion).trim();
	}
	
	if(config.skipUrlPatterns) {
		skipUrlPatterns = [];
		for( i = 0, len = config.skipUrlPatterns.length; i < len; i++) {
			if(util.isRegExp(config.skipUrlPatterns[i])) {
				skipUrlPatterns.push(config.skipUrlPatterns[i]);
			} else {
				skipUrlPatterns.push(new RegExp('^' + config.skipUrlPatterns[i] + '.*$'));
			}
		}
	}

	return authenticate;
};


var getAppId = module.exports.getAppId = function() {
	return appId;
};

var getAppSecret = module.exports.getAppSecret = function() {
	return appSecret;
};

var redirectLoginForm = module.exports.redirectLoginForm = function(req, res) {
	var state, currentUrl, url;
	
	state = establishCSRFTokenState(req);
	currentUrl = getCurrentUrl(req);
	
	url = PROTOCOL + DOMAIN_MAP.www;
	
	if (apiVersion) {
		url += '/' + apiVersion;
	}
	
	url += '/dialog/oauth?client_id=' + appId + '&redirect_uri=' + currentUrl + '&scope=' + scope + '&state=' + state;
	
	redirect(res, url);
};

function authenticate(req, res, next) {
	var code, state, signedRequest, accessToken, expires, i;
	
	if(skipUrlPatterns) {
		for( i = 0, len = skipUrlPatterns.length; i < len; i++) {
			if(skipUrlPatterns[i].test(req.url)) {
				return next();
			}
		}
	}
	
	parseQuery(req);
	signedRequest = getSignedRequest(req);
	if(signedRequest && signedRequest.oauth_token) {
		setPersistentData(req, 'access_token', signedRequest.oauth_token);
		setPersistentData(req, 'expires', signedRequest.expires);
		setPersistentData(req, 'user_id', signedRequest.user_id);
		req.facebook = new Facebook(signedRequest.oauth_token, apiVersion);
		return next();
	}
	accessToken = getPersistentData(req, 'access_token');
	expires = getPersistentData(req, 'expires');
	if(accessToken && expires && validateExpires(req, expires)) {
		req.facebook = new Facebook(accessToken, apiVersion);
		return next();
	}
	code = req.query.code;
	state = req.query.state;

	if(code && state && state === getPersistentData(req, 'state')) {
		getAccessTokenFromCode(req, res, code, function(err, accessToken, expires) {
			if(accessToken) {
				setPersistentData(req, 'access_token', accessToken);
				setPersistentData(req, 'expires', expires);
				req.facebook = new Facebook(accessToken, apiVersion);
			} else if (err) {
				switch(err.code) {
					case 190:
					case 102:
						destroySession(req, res);
					break;
				}	
			}
			next();
		});
		return;
	}
	/* Not login; save data */
	saveRequestData(req);
	redirectLoginForm(req, res);
}

/**
 * 
 */

var saveRequestData = function(req) {
	var data = {
		body: req.body,
		params: req.params,
		query: req.query,
		files: req.files
	};
	if (!req.session) {
		return;
	}
	req.session[REQUEST_DATA_SESSION_KEY] = data;
};

/**
 *
 * @param {Object} req
 * @param {Object} res
 * @param {Function} clearCookie
 *  clearCookie is optional
 *  And will be called with the name of signed request cookie.
 *  Default behavior is to try using setHeader from ServerResponse class
 *  Can be good if application has a better cookie handler
 */
var destroySession = module.exports.destroySession = function(req, res, clearCookie) {
	var cookieName = getSignedRequestCookieName();
	var clearCookie = clearCookie || (function(cookieName) {
		var cookies, fbsrCookie;
		try {
			fbsrCookie = cookieName + '=; path=/; expires=' + new Date(0).toUTCString();
			cookies = res.getHeader('Set-Cookie');
			if(cookies) {
				if(util.isArray(cookies)) {
					cookies.push(fbsrCookie);
				} else {
					cookies = [cookies, fbsrCookie];
				}
			} else {
				cookies = fbsrCookie;
			}
			res.setHeader('Set-Cookie', cookies);
		} catch(e) {
			console.error('Could not invalidate cookie');
		}
	});
	
	if(req.facebook) {
		req.facebook._setAccessToken(null);
		delete req.facebook;
	}
	clearAllPersistentData(req);
	if(req.cookies && req.cookies.hasOwnProperty(cookieName)) {
		delete req.cookies[cookieName];
		clearCookie(cookieName);
	}
};

var FacebookError = function(data) {
	Error.call(this);
	this.error_subcode = null;
	this.type = null;
	this.code = null;
	this.statusCode = null;
	this.parse(data);
};

util.inherits(FacebookError, Error);

FacebookError.prototype.parse = function(data) {
	var jsonData;
	try {
		jsonData = JSON.parse(data);
	} catch(e) {
		jsonData = {};
	}
	if(jsonData.error) {
		this.message = jsonData.error.message;
		this.code = jsonData.error.code;
		if (jsonData.error.error_subcode) {
			this.error_subcode = jsonData.error.error_subcode;
		}
		this.type = jsonData.error.type;
	}
};


var Facebook = module.exports.Facebook = function(accessToken, apiVersion) {
	this._accessToken = null;
	this._my = null;
	this._apiVersion = ''
	if(accessToken) {
		this._setAccessToken(accessToken);
	}
	apiVersion = String(apiVersion).trim()
	if (apiVersion) {
		this._apiVersion = apiVersion;
	}
};

Facebook.prototype = {
	_setAccessToken : function(accessToken) {
		this._accessToken = accessToken;
	},
	_getAccessToken : function() {
		return this._accessToken;
	},
	_graph : function(options, callback) {
		var req = https.request(options, function(res) {
			var data = '';
			res.on('data', function(chunk) {
				data += chunk;
			});
			res.on('end', function() {
				try {
					if(res.statusCode === 200) {
						return callback(null, JSON.parse(data));
					} else {
						/* Give application possibility to decide what to do */
						error = new FacebookError(data);
						error.statusCode = res.statusCode;
						return callback(error, null);
					}
				} catch(e) {/* json parse may throw error */
					return callback(e, null);
				}
			});
		}).on('error', function(err) {
			callback(err, null);
		});
		
		req.end();
	},
	_build_options : function(path, method, params) {
		if(path.indexOf('?') !== -1) {
			if(path[path.length - 1] !== '?' && path[path.length - 1] !== '&') {
				path += '&';
			}
		} else {
			path += '?';
		}
		if (params) {
			path += this._params_to_query(params) + '&';
		}
		
		if (this._getAccessToken()) {
			path += 'access_token=' + this._getAccessToken();
		}
		
		return {
			host : DOMAIN_MAP.graph,
			path : this._apiVersion? '/' + this._apiVersion + path : path,
			port: 443,
			headers : {
				'User-Agent' : USER_AGENT
			},
			method : method
		};
		
	},
	_params_to_query : function(params) {
		if (typeof params === 'object') {
			return querystring.stringify(params);
		}
		return params;
	},
	post : function(path, params, callback) {
		if (typeof callback === undefined) {
			callback = params;
			params = null;
		}
		this._graph(this._build_options(path, 'POST', params), callback);
	},
	delete : function(path, callback) {
		this._graph(this._build_options(path, 'DELETE'), callback);
	},
	update : function(path, params, callback) {
		this.post(path, params, callback);
	},
	graph : function(path, callback) {
		this._graph(this._build_options(path, 'GET'), callback);
	},
	search : function(params, callback) {
		this._graph(this._build_options('/search', 'GET', params), callback);
	},
	fql : function(query, callback) {
		var encodedQuery, path;
		
		if( query instanceof Object) {
			encodedQuery = encodeURIComponent(JSON.stringify(query));
		} else {
			encodedQuery = encodeURIComponent(query);
		}
		path = '/fql?q=' + encodedQuery + '&format=json';
		
		this._graph(this._build_options(path, 'GET'), callback);
	},
	me : function(callback, fields) {
		var meUrl = '/me' + ( fields ? '?fields=' + fields : '');
		this.graph(meUrl, callback);
	},
	get my() {
		if (!this._my) {
			this._my = new My(this);
		}
		return this._my;
	},
	getAppFriends : function(callback, fields) {
		var fields, fql;
		
		fields = (fields? fields : DEFAULT_USER_FIELDS);
		fql = 'SELECT ' + fields + ' FROM user WHERE uid IN (SELECT uid2 FROM friend WHERE uid1=me()) AND is_app_user = 1';
		this.fql(fql, callback);
	}
}

/**
 * Connected to Object me for doing query like /me/connectionType, for instance /me/friends
 */
var My = function(facebook) {
	this.facebook = facebook;
};

My.prototype._meConnection = function(connectionType, callback, params) {
	var meUrl = '/me/' + connectionType + ( params ? '?' + params : '');
	this.facebook.graph(meUrl, callback);
};

My.prototype.connection = function(connectionType, callback, params) {
	this._meConnection(connectionType, callback, params);
};

['friends', 'feed', 'likes', 'movies', 'music', 'books', 'albums',
	'notes', 'permissions', 'photos', 'videos', 'events', 'groups',
	'checkins', 'locations'].forEach(function (connectionType) {
  My.prototype[connectionType] = function (callback, params) {
    this._meConnection.apply(this, [connectionType, callback, params]);
  };
});

function getAccessTokenFromCode(req, res, code, callback) {
	var query, options;
	
	query = '';
	if (apiVersion) {
		query += '/' + apiVersion;
	}
	
	query += '/oauth/access_token?client_id=' + appId + '&redirect_uri=' + getCurrentUrl(req) + '&client_secret=' + appSecret + '&code=' + code;
	
	options = {
		host : DOMAIN_MAP.graph,
		path : query,
		headers : {
			'User-Agent' : USER_AGENT
		}
	};

	https.get(options, function(r) {
		var data = '';
		
		r.on('data', function(chunk) {
			data += chunk;
		});
		r.on('end', function() {
			var parsedUrl, error;
			
			if(r.statusCode === 200) {
				try {
					parsedUrl = url.parse('http://fakedomain.test?' + data, true);
					/* expires is relative so adding from now */
					return callback(null, parsedUrl.query.access_token, Math.floor(Date.now() / 1000) + parsedUrl.query.expires);
				} catch(e) {
					console.error(e);
					return callback(e, null, null);
				}
			} else {
				console.error(data);
				error = new FacebookError(data);
				error.statusCode = r.statusCode;
				return callback(error, null, null);
			}
		});
	}).on('error', function(err) {
		callback(err, null, null);
	});
}

function getCurrentUrl(req) {
	return encodeURIComponent(redirectUri);
}

function redirect(res, url) {
	res.end('<script type="text/javascript">top.location.href="' + url + '"</script>');
}

function parseSignedRequest(signedRequest) {
	var sig, data, expectedSig, payload;
	
	payload = signedRequest.split('.');
	expectedSig = payload[0];
	try {
		data = JSON.parse(new Buffer(payload[1], 'base64').toString());
	} catch(e) {
		return null;
	}
	if(data.algorithm.toUpperCase() !== 'HMAC-SHA256') {
		console.log('Unknown signed_request hash algorithm: ' + data.algorithm + '. Expected HMAC-SHA256');
		return null;
	}
	sig = crypto.createHmac('sha256', appSecret);
	sig.update(payload[1]);
	sig = sig.digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');

	if(sig !== expectedSig) {
		console.log('Bad signed_request! Expected: ' + expectedSig + ' but got: ' + sig);
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
	var state, shasum = crypto.createHash('md5');
	
	shasum.update((Math.random() * (new Date().getTime())).toString());
	state = shasum.digest('hex');
	setPersistentData(req, 'state', state);
	return state;
}

function setPersistentData(req, key, value) {
	if(SUPPORT_KEYS.indexOf(key) === -1) {
		throw new Error('Does not support key: ' + key);
	}
	if (!req.session) {
		throw new Error('Need session enable to be able to persist data');
	}
	req.session[getSessionKey(key)] = value;
}

function getPersistentData(req, key, defaultValue) {
	if(SUPPORT_KEYS.indexOf(key) === -1) {
		throw new Error('Does not support key: ' + key);
	}
	if (!req.session) {
		return null;
	}
	key = getSessionKey(key);
	return req.session.hasOwnProperty(key) ? req.session[key] : (defaultValue === undefined) ? null : defaultValue;
}

function clearPersistentData(req, key) {
	if(SUPPORT_KEYS.indexOf(key) === -1) {
		throw new Error('Does not support key: ' + key);
	}
	if (!req.session) {
		return;
	}
	delete req.session[getSessionKey(key)];
}

function clearAllPersistentData(req) {
	var i, len;
	if (!req.session) {
		return;
	}
	for (i = 0, len = SUPPORT_KEYS.length; i < len; i++) {
		delete req.session[getSessionKey(SUPPORT_KEYS[i])];
	}
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