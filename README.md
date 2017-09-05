# OAuth 2.0 for WordPress

Connect applications to your WordPress site without ever giving away your password.

This plugin uses the OAuth 2 protocol to allow delegated authorization; that is, to allow applications to access a site using a set of secondary credentials. This allows server administrators to control which applications can access the site, as well as allowing users to control which applications have access to their data.

This plugin only supports WordPress >= 4.8.

## Proof Key for Code Exchange
OAuth2 plugin supports PKCE as a protection against authorization code interception attack (relevant only for authorization code grant type). In order to use PKCE, on the initial authorization request, add two fields: 
* _code_challenge_ 
* _code_challenge_method_ (optional). 

Code verifier is a 43-128 length random string consisting of [A-Z] / [a-z] / [0-9] / "-" / "." / "_" / "~". Code challenge is derived from the code verifier depending on the challenge method. Two types are supported, 's256' and 'plain'. Plain is just code_challenge = code_verifier. s256 method uses SHA256 to hash the code verifier and then do a base64 encoding of the resulting hash. e.g.

code_verifier = 052edd3941bb8040ecac75d2359d7cd1abe2518911b<br>
code_challenge = base64( sha256( code_verifier ) ) = MmNmZTJlNGZhYmNmYzQ3YTI4MmRhY2Q1NGEwZDUzZTFiZGFhNTNlODI4MGY3NjM0YWUwNjA1YjYzMmQwNDMxNQ==<br>
code_challenge_method = s256

In the next step, when using the code received from the server to obtain an access token, code_verifier must be passed in as an additional field to the request, and it must be using the code_verifier value that was used to calculate the code_challenge in the initial request.

## CLI Commands

### PKCE

A custom WP CLI helper command to generate a random code verifier and a code challenge.

```wp oauth2 generate-code-challenge```

## Warning

This is in extremely early beta, and does not work yet. Please help us out and contribute!


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
