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

Documents are cached for 5 to 60 minutes, based on the `Cache-Control` header of the response. When a refresh fails for a temporary reason, the plugin keeps using the stored client. When it fails for a permanent reason, such as a 404 or an invalid document, the stored client is marked as failed. New authorizations and the fallback to the stored client are blocked until a refresh succeeds. Codes that were already issued (they last up to 10 minutes) and existing tokens keep working until a later successful refresh changes the generation, or an admin deletes the client.

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

The plugin checks the result. It must be an array with a whole number `limit` of 0 or more and a whole number `window` of 1 or more. Numeric strings are cast to integers. Anything else is ignored and the default for the scope is used.

Sets how many documents may be fetched in a time window. It runs once for each scope. The scope is `user` for one user, or `global` for all users of a site. On a network each site has its own counters. The defaults are 10 fetches per 600 seconds per user, and 60 fetches per 600 seconds per site.

The filter gets the default `limit` and `window` for the scope. Change either or both and return the array.

```php
add_filter(
	'oauth2.cimd.rate_limit',
	function ( $limit, $user_id, $scope ) {
		if ( 'user' === $scope ) {
			// Allow 5 fetches per user every 300 seconds.
			$limit['limit']  = 5;
			$limit['window'] = 300;
		}

		if ( 'global' === $scope ) {
			// Allow 120 fetches per site every 600 seconds.
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

## Issuer and the iss parameter

Every authorization response redirect carries an `iss` parameter (RFC 9207), for all clients and not only CIMD ones. It holds the issuer of the authorization server. The `iss` value always matches the `issuer` in the metadata at `/.well-known/oauth-authorization-server`, which also sets `authorization_response_iss_parameter_supported` to `true`. The issuer is also the `authorization_servers` entry of the protected resource metadata.

The issuer is the site URL by default. Change it with the `oauth2.well_known_authorization_server_metadata` filter, by setting the `issuer` field. The `iss` parameter, the protected resource metadata and the check that refuses the issuer as a client ID all use that value.

```php
add_filter(
	'oauth2.well_known_authorization_server_metadata',
	function ( $metadata ) {
		$metadata['issuer'] = 'https://auth.example.com';

		return $metadata;
	}
);
```

RFC 8414 and RFC 9207 expect an `https` issuer. A site that is served over `http` publishes an `http` issuer, and a strict client may reject it.

## Blocking a client

Do not delete the client record to block a client. The record is created again the next time someone uses the client ID.

Block the client with a filter instead. Return `false` from `oauth2.cimd.admit_url` for the URL or its host, or return `deny` from `oauth2.cimd.policy`. Both take effect at once for authorize, the token endpoint and bearer tokens.

## Limits and where they are stored

Each client has one record. Its metadata, expiry, generation, security hash and failure marker are stored together as one value, so a refresh replaces all of them in a single write. After the write the plugin reads the value back from the database. If it does not match, the refresh returns an error and the stored value is not trusted. Only a write that the database refuses leaves the previous value in place. A new record that cannot be read back is deleted.

Fetches are limited per user (10 per 600 seconds) and per site (60 per 600 seconds). On a network the limits are kept for each site, so a user who reaches the limit on one site can still fetch on another, and one site cannot use up the budget of the others. Only a real fetch counts. A request that is served from the cache, or that finds another request already fetching the same URL, does not count. Use the `oauth2.cimd.rate_limit` filter to change the limits.

Only one request fetches a given URL at a time. The lock is a row in the options table of the main site, shared by the whole network, because one URL has one document whichever site asks. A database insert takes it, and only the request that holds it can release it. A lock lasts at most 30 seconds, after which another request can take it over.

Where the counters are stored depends on the object cache:

* With an external object cache, both counters live in the object cache, in the `oauth2_cimd` group, with the site ID in the key. The counters are atomic.
* Without one, the per-user counter is a user option, which WordPress stores per site as `{prefix}oauth2_cimd_rl_{user ID}` in the user meta table. The per-site counter is a regular transient of the site, `oauth2_cimd_rl_global`. Each holds a `count` and a `reset` time. The per-user row is deleted when it is read after its window has expired, so it exists only while a window is active or recently used. The counters are read and then written, so under heavy parallel load the limit is soft and may be passed by a few requests.

## Rate limiting at the web server

Each document fetch makes your server send a request to another site. The limits above are a backstop. Limit requests at the web server first. This stops a flood before PHP runs and before any database write.

Limit the login script and the OAuth REST routes only, so the rest of the site is not affected. Match on the path, not on the query string or the request body. The `action` argument can be repeated, written in another case, encoded, or sent in a POST body, so a rule that depends on it is easy to get around. This means the limit covers all of `wp-login.php`, not only the authorize screen, so set the rate to a generous value.

### nginx

Use a `map` on `$uri` so that the limit applies to these paths only. `$uri` is decoded and normalised by nginx, and `~*` makes the match case-insensitive. The `(/|$)` ending also matches path info, such as `/wp-login.php/x`. Requests that map to an empty key are not limited.

```nginx
# In the http block.
map $uri $oauth2_limit_key {
    default                     "";
    "~*^/wp-login\.php(/|$)"    $binary_remote_addr;
    ~*^/wp-json/oauth2/         $binary_remote_addr;
}

limit_req_zone $oauth2_limit_key zone=oauth2:10m rate=60r/m;
limit_req_status 429;

# In the server block.
limit_req zone=oauth2 burst=20 nodelay;
```

Put `limit_req` in the server block only. Inside a PHP location it does not work for REST routes. The `try_files` rule sends them to `/index.php` with an internal redirect, and `$uri` is `/index.php` from then on, so the map finds no match. A server-level `limit_req` is inherited only by locations that do not define their own. If your `\.php$` location already has a `limit_req`, add the `oauth2` zone there as well, so that `wp-login.php` is still limited. Do not add a new `location = /wp-login.php`, because it would replace your PHP handling for that file.

Use pretty permalinks. With plain permalinks the token endpoint is `/index.php?rest_route=/oauth2/access_token`, and a path-based limit would have to cover all of `index.php`.

### Apache

`mod_evasive` counts requests for the whole site and cannot be limited to a few paths, so it is not a good fit here. Use `mod_security` instead. The rule below counts requests to these paths for each client address and denies the client when the count is too high. It matches on `REQUEST_FILENAME`, which is the path without the query string. The transformations decode percent-escapes, remove path tricks and ignore case. The `(/|$)` ending also matches path info, such as `/wp-login.php/x`. It is a starting point, so adjust the limit to your traffic.

```apache
<IfModule mod_security2.c>
    SecAction "id:9100100,phase:1,nolog,pass,initcol:ip=%{REMOTE_ADDR}"

    SecRule REQUEST_FILENAME "@rx ^/(wp-login\.php(/|$)|wp-json/oauth2/)" \
        "id:9100101,phase:1,nolog,pass,t:urlDecodeUni,t:normalizePath,t:lowercase,setvar:ip.oauth2_count=+1,expirevar:ip.oauth2_count=60"

    SecRule IP:OAUTH2_COUNT "@gt 60" \
        "id:9100102,phase:1,deny,status:429,msg:'Too many OAuth requests'"
</IfModule>
```

### Behind a proxy or CDN

If your site is behind a proxy, load balancer or CDN, the web server sees the address of the proxy, not the visitor. Every visitor then shares one limit. Set up real client addresses first. In nginx use `set_real_ip_from` and `real_ip_header`. In Apache use `mod_remoteip` with `RemoteIPHeader` and `RemoteIPInternalProxy`. Only trust the headers of proxies you control.

These are the first line of defence. The limits in the plugin are a backstop for the case where the web server is not set up to limit requests.
