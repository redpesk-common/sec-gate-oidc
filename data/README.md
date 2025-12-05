# Basic example

## home page

The home page is served by `/htdocs/index.html`.

At init, it calls the javascript function `init()`.

It offers links to several paths that are protected.

When such a path is requested, the sec-gate enforce
identification using an IDP using the login page.

## login page


the login page is served by /hidden/idps/common/login.html

At init, it calls the javascript function `init(getConfigIdps)`.

iThe function `init`is in /htdocs/jscss/sgate-binding.js.
After connecting to the binder, it invokes the given callback,
here `getConfigIdps`.

The function `getConfigIdps` is in the file `/htdocs/jscss/sgate-glue.js`.
It invokes the verb `idp-query-conf`. That verb returns a 



