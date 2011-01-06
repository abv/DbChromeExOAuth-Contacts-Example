function DbChromeExOAuth(url_request_token, url_auth_token, url_access_token, consumer_key, consumer_secret, oauth_scope, opt_args, token_id) {
  ChromeExOAuth.call(this, url_request_token, url_auth_token, url_access_token, consumer_key, consumer_secret, oauth_scope, opt_args);
  this.token_id = token_id;
  this.callback_page = opt_args && opt_args['callback_page'] || "db_chrome_ex_oauth.html";
}

DbChromeExOAuth.prototype = new ChromeExOAuth();
DbChromeExOAuth.prototype.constructor = DbChromeExOAuth;

/*
 * These two functions interact with the database
 */

DbChromeExOAuth.prototype.getTokenRecord = function(callback) {
  var bg = chrome.extension.getBackgroundPage();
  bg.MyTable.load(this.token_id, function(result){
    result.markDirty('data');
    callback(result.data);
  });
}

DbChromeExOAuth.prototype.flushTokenRecord = function(callback) {
  var bg = chrome.extension.getBackgroundPage();
  bg.persistence.flush(function(){
    callback()
  });
}

/*
 * Extending methods from ChromeExOAuth as needed...
 */

DbChromeExOAuth.initBackgroundPage = function(oauth_config) {
  window.oauth_dance[oauth_config.token_id].chromeExOAuthConfig = oauth_config;
  window.oauth_dance[oauth_config.token_id].chromeExOAuth = DbChromeExOAuth.fromConfig(oauth_config);
  window.oauth_dance[oauth_config.token_id].chromeExOAuthRedirectStarted = false;
  window.oauth_dance[oauth_config.token_id].chromeExOAuthRequestingAccess = false;

  var url_match = chrome.extension.getURL(window.oauth_dance[oauth_config.token_id].chromeExOAuth.callback_page);
  var tabs = {};
  chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    if (changeInfo.url &&
        changeInfo.url.substr(0, url_match.length) === url_match &&
        changeInfo.url != tabs[tabId]) {
          var params = DbChromeExOAuth.getQueryStringParams(changeInfo.url);
          if (oauth_config.token_id == params.automato_token_id && window.oauth_dance[params.automato_token_id].chromeExOAuthRequestingAccess == false) {
              chrome.tabs.create({ 'url' : changeInfo.url }, function(tab) {
                tabs[tab.id] = tab.url;
                chrome.tabs.remove(tabId);
              });
          }
    }
  });
  return window.oauth_dance[oauth_config.token_id].chromeExOAuth;
};

DbChromeExOAuth.prototype.initOAuthFlow = function(callback) {
  var scope = this;
  this.hasToken(function(){
    scope.getTokenAndSecret(function(token, secret){
      callback(token, secret);
    });
  }, function(){
    var params = DbChromeExOAuth.getQueryStringParams();
    if (params['chromeexoauthcallback'] == 'true') {
      var oauth_token = params['oauth_token'];
      var oauth_verifier = params['oauth_verifier']
      scope.getAccessToken(oauth_token, oauth_verifier, callback);
    } else {
      var request_params = {
        'url_callback_param' : 'chromeexoauthcallback'
      }
      scope.getRequestToken(function(url) {
        window.location.href = url;
      }, request_params);
    }
  });
};

DbChromeExOAuth.prototype.clearTokens = function(callback) {
  var scope = this;
  this.getTokenRecord(function(token){
    delete token[scope.key_token];
    delete token[scope.key_token_secret];
    scope.flushTokenRecord(function(){
	  callback();
    });
  });
};

DbChromeExOAuth.prototype.hasToken = function(callbackTrue, callbackFalse) {
  this.getToken(function(token){
    if (token) {
      callbackTrue();
    } else {
      callbackFalse();
    }
  });
};

DbChromeExOAuth.prototype.getToken = function(callback) {
  var scope = this;
  this.getTokenRecord(function(record){
    if (record[scope.key_token]) {
      callback(record[scope.key_token]);
    } else {
      callback(false);
    }
  });
};

DbChromeExOAuth.prototype.getTokenAndSecret = function(callback) {
  var scope = this;
  this.getTokenRecord(function(token){
    callback(token[scope.key_token], token[scope.key_token_secret]);
  });
};

DbChromeExOAuth.prototype.getTokenSecret = function(callback) {
  var scope = this;
  this.getTokenRecord(function(token){
    callback(token[scope.key_token_secret]);
  });
};

ChromeExOAuth.prototype.setTokenSecret = function(secret, callback) {
  var scope = this;
  this.getTokenRecord(function(token){
    token[scope.key_token_secret] = secret;
    scope.flushTokenRecord(function(){
	  callback();
    });
  });
};

ChromeExOAuth.prototype.setTokenAndSecret = function(token_value, secret_value, callback) {
  var scope = this;
  this.getTokenRecord(function(token){
    token[scope.key_token] = token_value;
    token[scope.key_token_secret] = secret_value;
    scope.flushTokenRecord(function(){
	  callback();
    });
  });
};

DbChromeExOAuth.prototype.authorize = function(callback) {
  var scope = this;
  this.hasToken(function(){
    scope.getTokenAndSecret(function(token, secret){
      callback(token, secret);
    });
  }, function(){
    window.oauth_dance[scope.token_id].chromeExOAuthOnAuthorize = function(token, secret) {
      callback(token, secret);
    };
    chrome.tabs.create({ 'url' :chrome.extension.getURL(scope.callback_page + '?automato_token_id=' + scope.token_id) });
  });
};

DbChromeExOAuth.prototype.getAccessToken = function(oauth_token, oauth_verifier,
                                                  callback) {
  if (typeof callback !== "function") {
    throw new Error("Specified callback must be a function.");
  }
  var bg = chrome.extension.getBackgroundPage();
  if (bg.oauth_dance[this.token_id].chromeExOAuthRequestingAccess == false) {
    bg.oauth_dance[this.token_id].chromeExOAuthRequestingAccess = true;
    var scope = this;
    this.getTokenSecret(function(secret){
	    var result = OAuthSimple().sign({
	      path : scope.url_access_token,
	      parameters: {
	        "oauth_token" : oauth_token,
	        "oauth_verifier" : oauth_verifier
	      },
	      signatures: {
	        consumer_key : scope.consumer_key,
	        shared_secret : scope.consumer_secret,
	        oauth_secret : secret
	      }
	    });

	    var onToken = ChromeExOAuth.bind(scope.onAccessToken, scope, callback);
	    ChromeExOAuth.sendRequest("GET", result.signed_url, null, null, onToken);
    });
  }
};

DbChromeExOAuth.prototype.getRequestToken = function(callback, opt_args) {
  if (typeof callback !== "function") {
    throw new Error("Specified callback must be a function.");
  }
  var url = opt_args && opt_args['url_callback'] ||
            window && window.top && window.top.location &&
            window.top.location.href;

  var url_param = opt_args && opt_args['url_callback_param'] ||
                  "chromeexoauthcallback";
  var url_callback = ChromeExOAuth.addURLParam(url, url_param, "true");

  var result = OAuthSimple().sign({
    path : this.url_request_token,
    parameters: {
      "xoauth_displayname" : this.app_name,
      "scope" : this.oauth_scope,
      "oauth_callback" : url_callback
    },
    signatures: {
      consumer_key : this.consumer_key,
      shared_secret : this.consumer_secret
    }
  });
  var onToken = DbChromeExOAuth.bind(this.onRequestToken, this, callback);
  DbChromeExOAuth.sendRequest("GET", result.signed_url, null, null, onToken);
};

DbChromeExOAuth.prototype.onRequestToken = function(callback, xhr) {
  if (xhr.readyState == 4) {
    if (xhr.status == 200) {
      var params = ChromeExOAuth.formDecode(xhr.responseText);
      var token = params['oauth_token'];
      var scope = this;
      this.setTokenSecret(params['oauth_token_secret'], function(){
	      var url = ChromeExOAuth.addURLParam(scope.url_auth_token,
	                                          "oauth_token", token);
	      for (var key in scope.auth_params) {
	        if (scope.auth_params.hasOwnProperty(key)) {
	          url = ChromeExOAuth.addURLParam(url, key, scope.auth_params[key]);
	        }
	      }
	      callback(url);
      });
    } else {
      throw new Error("Fetching request token failed. Status " + xhr.status);
    }
  }
};

DbChromeExOAuth.prototype.onAccessToken = function(callback, xhr) {
  var scope = this;
  if (xhr.readyState == 4) {
    var bg = chrome.extension.getBackgroundPage();
    if (xhr.status == 200) {
      var params = ChromeExOAuth.formDecode(xhr.responseText);
      var token = params["oauth_token"];
      var secret = params["oauth_token_secret"];
      this.setTokenAndSecret(token, secret, function(){
        bg.oauth_dance[scope.token_id].chromeExOAuthRequestingAccess = false;
        callback(token, secret);
      });
    } else {
      bg.oauth_dance[scope.token_id].chromeExOAuthRequestingAccess = false;
      throw new Error("Fetching access token failed with status " + xhr.status);
    }
  }
};

ChromeExOAuth.prototype.sendSignedRequest = function(url, callback,
                                                     opt_params) {
  var method = opt_params && opt_params['method'] || 'GET';
  var body = opt_params && opt_params['body'] || null;
  var params = opt_params && opt_params['parameters'] || {};
  var headers = opt_params && opt_params['headers'] || {};

  this.signURL(url, method, params, function(signedUrl){
	  ChromeExOAuth.sendRequest(method, signedUrl, headers, body, function (xhr) {
	    if (xhr.readyState == 4) {
	      callback(xhr.responseText, xhr);
	    }
	  });
  });
};

DbChromeExOAuth.prototype.signURL = function(url, method, opt_params, callback) {
  var scope = this;
  this.getTokenAndSecret(function(token, secret){
	  if (!token || !secret) {
	    throw new Error("No oauth token or token secret");
	  }

	  var params = opt_params || {};

	  var result = OAuthSimple().sign({
	    action : method,
	    path : url,
	    parameters : params,
	    signatures: {
	      consumer_key : scope.consumer_key,
	      shared_secret : scope.consumer_secret,
	      oauth_secret : secret,
	      oauth_token: token
	    }
	  });

	  callback(result.signed_url);
  });
};

DbChromeExOAuth.fromConfig = function(oauth_config) {
  return new DbChromeExOAuth(
    oauth_config['request_url'],
    oauth_config['authorize_url'],
    oauth_config['access_url'],
    oauth_config['consumer_key'],
    oauth_config['consumer_secret'],
    oauth_config['scope'],
    {
      'app_name' : oauth_config['app_name'],
      'auth_params' : oauth_config['auth_params']
    },
    oauth_config['token_id']
  );
};

DbChromeExOAuth.initCallbackPage = function() {
  console.log(chrome.extension);
  var params = DbChromeExOAuth.getQueryStringParams();
  var background_page = chrome.extension.getBackgroundPage();
  var oauth_dance = background_page.oauth_dance[params.automato_token_id];
  var oauth_config = oauth_dance.chromeExOAuthConfig;
  var oauth = DbChromeExOAuth.fromConfig(oauth_config);
  background_page.chromeExOAuthRedirectStarted = true;
  oauth.initOAuthFlow(function (token, secret) {
    oauth_dance.chromeExOAuthOnAuthorize(token, secret);
    oauth_dance.chromeExOAuthRedirectStarted = false;
    chrome.tabs.getSelected(null, function (tab) {
      chrome.tabs.remove(tab.id);
    });
  });
};

DbChromeExOAuth.getQueryStringParams = function(url) {
  var urlparts;
  if (url) {
    urlparts = url.split("?");
  } else {
    urlparts = window.location.href.split("?");
  }
  if (urlparts.length >= 2) {
    var querystring = urlparts.slice(1).join("?");
    return ChromeExOAuth.formDecode(querystring);
  }
  return {};
};

DbChromeExOAuth.sendRequest = function(method, url, headers, body, callback) {
  var xhr = new XMLHttpRequest();
  xhr.onreadystatechange = function(data) {
    callback(xhr, data);
  }
  xhr.open(method, url, true);
  if (headers) {
    for (var header in headers) {
      if (headers.hasOwnProperty(header)) {
        xhr.setRequestHeader(header, headers[header]);
      }
    }
  }
  xhr.send(body);
};

DbChromeExOAuth.bind = function(func, obj) {
  var newargs = Array.prototype.slice.call(arguments).slice(2);
  return function() {
    var combinedargs = newargs.concat(Array.prototype.slice.call(arguments));
    func.apply(obj, combinedargs);
  };
};