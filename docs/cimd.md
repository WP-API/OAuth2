# Client ID Metadata Documents

## What it is

A Client ID Metadata Document (CIMD) lets an app use an HTTPS URL as its client ID. The URL points to a JSON document that describes the app: its name, its redirect URIs and how it authenticates. The app does not need to be registered on your site first.

CIMD is on by default. The authorization server metadata at `/.well-known/oauth-authorization-server` advertises it with `client_id_metadata_document_supported`.

## How it works

When a logged-in user opens the authorize screen with a client ID that starts with `https://`, the plugin fetches the document and checks it. It stores the result as a client record, and the consent screen shows the app's name and where it is published.

The plugin never fetches a document for a logged-out visitor. The visitor is sent to the login page first, and the document is fetched after login.

The plugin treats these clients as public clients:

* They have no secret. A request that sends a client secret is refused.
* PKCE is always required. The `oauth2.pkce.required` filter does not change this.
* They cannot use the `client_credentials` grant.
* Redirect URIs must match a URI in the document exactly. The one exception is a loopback `http` URI (`localhost`, `127.0.0.1` or `[::1]`), which may use any port.

A client record is tied to the document it came from. If the redirect URIs change in a refresh, all tokens and codes issued before the change stop working. With the `manual` policy the client also goes back to draft until an admin approves it again.

Documents are cached for 5 to 60 minutes, based on the `Cache-Control` header of the response. When a refresh fails for a temporary reason, the plugin keeps using the stored client. When it fails for a permanent reason, such as a 404 or an invalid document, the stored client is no longer used until a refresh succeeds.

## Filters

### oauth2.cimd.enabled

Turns CIMD on or off. When it is off, CIMD client IDs are treated as unknown, including ones that were stored before.

```php
add_filter( 'oauth2.cimd.enabled', '__return_false' );
```

### oauth2.cimd.admit_url

Decides whether a client ID URL may be used. It runs on every lookup, not only when a document is fetched.

```php
add_filter(
	'oauth2.cimd.admit_url',
	function ( $admit, $url ) {
		return 'example.com' === wp_parse_url( $url, PHP_URL_HOST ) ? $admit : false;
	},
	10,
	2
);
```

### oauth2.cimd.policy

Decides what happens to a client. The value is `auto`, `manual` or `deny`.

* `auto` approves a new client at once. This is the default.
* `manual` saves a new client as a draft. An admin has to publish it.
* `deny` refuses the client. It also stops a stored client from authorizing, exchanging codes or authenticating.

An existing client keeps its status. A refresh never approves or unapproves it. The one exception is a change to the redirect URIs, which sends a published client back to draft under `manual`.

```php
add_filter(
	'oauth2.cimd.policy',
	function ( $policy, $metadata, $url, $existing ) {
		return null === $existing ? 'manual' : $policy;
	},
	10,
	4
);
```

### oauth2.cimd.rate_limit

Sets how many documents may be fetched in a time window. It runs once for each scope. The scope is `user` for one user, or `global` for all users across the network. The defaults are 10 fetches per 600 seconds per user, and 60 fetches per 600 seconds overall.

```php
add_filter(
	'oauth2.cimd.rate_limit',
	function ( $limit, $user_id, $scope ) {
		if ( 'global' === $scope ) {
			$limit['limit'] = 120;
		}

		return $limit;
	},
	10,
	3
);
```

### oauth2.cimd.cache_ttl

Sets how many seconds a fetched document is cached. The value is already limited to 300 to 3600 seconds.

```php
add_filter(
	'oauth2.cimd.cache_ttl',
	function ( $ttl ) {
		return 900;
	}
);
```

### oauth2.cimd.allow_loopback

Lets the plugin fetch documents from loopback addresses. Use it for local development only, with a host name that resolves to `127.0.0.1`.

```php
add_filter( 'oauth2.cimd.allow_loopback', '__return_true' );
```

## Blocking a client

Do not delete the client record to block a client. The record is created again the next time someone uses the client ID.

Block the client with a filter instead. Return `false` from `oauth2.cimd.admit_url` for the URL or its host, or return `deny` from `oauth2.cimd.policy`. Both take effect at once for authorize, the token endpoint and bearer tokens.

## Limits and where they are stored

Fetches are limited per user (10 per 600 seconds) and across the network (60 per 600 seconds). Only a real fetch counts. A request that is served from the cache, or that finds another request already fetching the same URL, does not count.

Only one request fetches a given URL at a time. A lock lasts at most 30 seconds.

If your site uses an external object cache, the locks and counters live in the object cache, in a global group shared by all sites of a network. The counters are atomic.

If it does not, the locks are rows in the options table of the main site, and the counters are site transients. These are shared by the whole network. The counters are read and then written, so under heavy parallel load the limit is soft and may be passed by a few requests.

## Rate limiting at the web server

Each document fetch makes your server send a request to another site. The limits above are a backstop. Limit requests at the web server first. This stops a flood before PHP runs and before any database write.

Limit only the authorize page and the token endpoint, so the rest of the site is not affected.

### nginx

Use a `map` so that the limit applies to these requests only. Requests that map to an empty key are not limited. The key joins the path and the `action` query argument, so only the authorize page of `wp-login.php` is matched.

```nginx
# In the http block.
map "$uri:$arg_action" $oauth2_limit_key {
    default                                   "";
    "/wp-login.php:oauth2_authorize"          $binary_remote_addr;
    ~^/wp-json/oauth2/access_token:           $binary_remote_addr;
}

limit_req_zone $oauth2_limit_key zone=oauth2:10m rate=30r/m;
limit_req_status 429;

# In the server block.
location = /wp-login.php {
    limit_req zone=oauth2 burst=10 nodelay;
    # ... your usual PHP handling.
}

location /wp-json/oauth2/access_token {
    limit_req zone=oauth2 burst=10 nodelay;
    # ... your usual PHP handling.
}
```

If your site does not use pretty permalinks, the token endpoint is `/index.php?rest_route=/oauth2/access_token`. Add a matching `location` and map entry for it.

### Apache

With `mod_evasive`, set limits for the whole site. It counts requests per client and per URL, so it works well for the authorize page.

```apache
<IfModule mod_evasive20.c>
    DOSHashTableSize    3097
    DOSPageCount        5
    DOSPageInterval     10
    DOSSiteCount        60
    DOSSiteInterval     10
    DOSBlockingPeriod   60
</IfModule>
```

With `mod_security`, count the requests to these two URLs for each client address, and deny the client when the count is too high. The rules below are a starting point. Adjust the limits to your traffic.

```apache
<IfModule mod_security2.c>
    SecAction "id:9100100,phase:1,nolog,pass,initcol:ip=%{REMOTE_ADDR}"

    SecRule REQUEST_URI "@beginsWith /wp-json/oauth2/access_token" \
        "id:9100101,phase:1,nolog,pass,setvar:ip.oauth2_count=+1,expirevar:ip.oauth2_count=60"

    SecRule REQUEST_URI "@beginsWith /wp-login.php" \
        "id:9100102,phase:1,nolog,pass,chain"
        SecRule ARGS:action "@streq oauth2_authorize" \
            "setvar:ip.oauth2_count=+1,expirevar:ip.oauth2_count=60"

    SecRule IP:OAUTH2_COUNT "@gt 30" \
        "id:9100103,phase:1,deny,status:429,msg:'Too many OAuth requests'"
</IfModule>
```

These are the first line of defence. The limits in the plugin are a backstop for the case where the web server is not set up to limit requests.
