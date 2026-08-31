# OAuth 2.0 for WordPress

Connect applications to your WordPress site without ever giving away your password.

This plugin uses the OAuth 2 protocol to allow delegated authorization; that is, to allow applications to access a site using a set of secondary credentials. This allows server administrators to control which applications can access the site, as well as allowing users to control which applications have access to their data.

This plugin only supports WordPress >= 4.8.

## Proof Key for Code Exchange (PKCE)

The plugin supports PKCE ([RFC 7636](https://tools.ietf.org/html/rfc7636)) for
the `authorization_code` grant, as protection against authorization code
interception. To use it, add two extra parameters to the initial
authorization request:

* `code_challenge` (required)
* `code_challenge_method` (optional, defaults to `plain`; use `S256`)

`S256` derives the challenge from a code verifier by SHA-256 hashing it, then
base64url-encoding the digest with no padding. For example:

```
code_verifier  = dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk
code_challenge = E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM
```

This is **not** the same as `base64_encode( hash( 'sha256', $verifier ) )` —
that encodes the hex digest with standard base64, which is a different, wrong
value that RFC 7636's own worked example above will catch.

When exchanging the code for a token, pass the original `code_verifier` as an
extra parameter to the token endpoint. The server derives the challenge from
it the same way and checks it matches the one supplied at authorization time.

A client can be marked to require PKCE from its edit screen under
**Users → Applications**. When required, only `S256` satisfies the
requirement — `plain` remains an accepted method generally, but does not
count as PKCE having been used, since it offers no protection against a
malicious app on the same device reading the authorization request.

Filters: `oauth2.pkce.supported_methods` (accepted `code_challenge_method`
values, default `S256` and `plain`), `oauth2.pkce.required_methods` (methods
that satisfy "PKCE required", default `S256` only), and `oauth2.pkce.required`
(override whether PKCE is required for a given client).

## CLI Commands

### PKCE

Generate a random code verifier and its matching code challenge, for manually
testing a PKCE flow:

```
wp oauth2 generate-code-challenge
```

## Contributors Welcome!

This plugin works and is in use in several production environments, but the user experience and documentation could be substantially improved. We welcome input and contributions to make this tool better!


## Credits

This plugin is licensed under the GNU General Public License v2 or later:

> Copyright 2017 by the contributors.
>
> This program is free software; you can redistribute it and/or modify
> it under the terms of the GNU General Public License as published by
> the Free Software Foundation; either version 2 of the License, or
> (at your option) any later version.
>
> This program is distributed in the hope that it will be useful,
> but WITHOUT ANY WARRANTY; without even the implied warranty of
> MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
> GNU General Public License for more details.
>
> You should have received a copy of the GNU General Public License
> along with this program; if not, write to the Free Software
> Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

Thanks to the contributors at the WCEU 2017 Contributor Day who were responsible for getting this plugin off the ground and into a usable state: @almirbi, @richardsweeney, @tfrommen.
