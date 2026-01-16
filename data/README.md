# Basic example

## home page

The home page is served by `/htdocs/index.html`.

At init, it calls the javascript function `init()`.

It offers links to several paths that are protected.

When such a path is requested, the sec-gate enforce
identification using an IDP using the login page.

## login page


the login page is served by /hidden/idps/common/login.html
that could be visible as sgate/common/login.html

At init, it calls the javascript function `init(getConfigIdps)`.

The function `init`is in /htdocs/jscss/sgate-binding.js.
After connecting to the binder, it invokes the given callback,
here `getConfigIdps`.

The function `getConfigIdps` is in the file `/htdocs/jscss/sgate-glue.js`.
It invokes the verb `idp-query-conf`. That verb returns an object containing
the list of idps and if available the target page (as alias):
{ "alias": ..., "idps": [ ... ] }. That reply is used for filling the
div "sgate-data". Each IDP data of the returned list is used to create a
button that jump to the 'login-url' of that idp.

Some IDP login pages are not served by sec-gate but are redirecting to
IDP login pages (ex: oidc, github, gitlab, ...). Some other are handled
by sec-gate (ex: ldap, pam, pcsc, ...). The later are call REDIRECTED LOGIN
and others are called DIRECT LOGIN.






