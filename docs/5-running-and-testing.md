# Running/Testing

afb-sec-gate-oidc is an afb-binder-v4 extension and cannot work with afb-binder-v3. \
Check with `afb-binder --version` that your version >= 4.0.0

## Requirements

* you should have a valid afb-binder > v4.0.0 installed.
* you should write or copy a sample oidc-config.json
* you should know the path to:

  * `libafb-sec-gate-oidc-ext.so` extension
  * `fedid-binding.so` binding
  * `libfedid-types.so` type converters

* you need a test client
  * `sec-gate-oidc` basic HTML/JS testing pages.
  * `sec-gate-webui` for one-page HTML Angular

If you run redpesk simply install the package with `dnf install sec-gate-oidc` for other platforms check redpesk [developer guide]({% chapter_link host-configuration-doc.setup-your-build-host %})

## set up your HTTPS/TLS environment

You need TLS certificate for your HTTPS connection. In development mode you may use `$SGATE/conf.d/project/ssl/gen-cert.sh` to generate as many as you need.

Generated certificate should be declared with "https-cert" and "https-key" of afb-binder configuration.

```json
  "https": true,
  "https-cert": "../conf.d/project/ssl/devel-cert.pem",
  "https-key": "../conf.d/project/ssl/devel-key.pem",
  "extension": "./package/lib/libafb-sec-gate-oidc-ext.so",
```

## make visible your HTML pages/applications

Make visible your HTML/JS files from sgate in order to expose it to client browser. For test you probably want to run everything with relative path from afb-binder rootdir.

```json
   "roothttp": ".",
   "rootdir":  "../conf.d/project/htdocs",
```

Note: if your application requires some absolute path use alias to make visible external to rootdir file to client browser.

```json
 "alias": [
    {"uid": "external-files", "url":"/browser-path", "path":"/path/on/disk" },
        ...
]
```

## Create/import HTML login pages

sgate ships two sets of login pages.

* Simple/HTML5: for developer to understand the protocols.
* Angular/HTML5: for people who need a modern and production oriented HTML5/UI.

First one is ship within source code ```$SOURCES/conf.d/project/htdocs```, second is ship through an independent package named ```sec-gate-webui```.

When installed your HTML pages should match with the global section of your configuration.
```json
     "globals": {
          "login": "/sgate/basic/login.html",
          "register": "/sgate/basic/register.html",
          "fedlink": "/sgate/basic/fedlink.html",
          "error": "/sgate/basic/error.html",
      },
```
'onepage' HTML5 url style is supported and configured URLs may include '#' and/or as many query list arguments as needed. The only constraint is that when using a query list configured URL should include a trailing '&'

```json
     "globals": {
          "login": "/sgate/onepage/myapp#login?style='cool'&",
          "register": "/sgate/onepage/myapp#register?style='cool'&",
          "fedlink": "/sgate/onepage/myapp#fedlink?style='cool'&",
          "error": "/sgate/onepage/myapp#error?style='cool'&",
      },
```

**WARNING**: global section uses browser URL not disk path. If URL/fullpath do not match afb-binder rootdir/httproot you should use the alias section to create an adequate match.

```json
"alias": [
    {"uid": "basic-html", "url":"/sgate/basic", "path":"idps/my-basic-html-pages" },
    {"uid": "smart-html", "url":"/sgate/onepage", "path":"idps/my-onepage-app" },
...
]
```

When correctly configured trying to access a protected resource, should redirect your browser to your login page. Either to select one IDP from a list, or directly to your IDP if you only use one.

## Configure your IDP

This is the most tricky part as configuration is specific to every IDP. Nevertheless all IDPs share equivalent requirements to register a new application:

* register as a developer, some like Google, Microsoft,... request a credit card, even if they promise that it is only to be sure that you are not a robot and that they will never use it.
* register an application: most IDP will ask for: name, logo, ...
* register application login redirect uri. This is the uri where your browser is redirected after a successful authentication. Note that this uri does not need to be visible from the IDP, it only has to be visible from your browser. As a result https://localhost:1324 or https://my-board.local can be valid.
* optionally they may ask a logout request. Note that contrarily to login uri the logout one should be directly accessible from the IDP. This is because logout is a back channel request that happens when user session terminates.

In order to test social authentication we recommend the 3 following authorities:

* [github](https://github.com/settings/applications/new): while not OpenID-connect but only oAuth2 compliant, Github remains very simple and flexible to use as identity authority. Furthermore as yourself and most of your developers bodies should already have an account it is a very simple option to share test/config with colleagues and friends.

* [phantauth](https://www.phantauth.net/): this is not a real identity authority but more a very friendly reference tool to test/debug applications. Phantauth does not require any registration. You may generate as many client-id as needed and login page only asks a login without password. Note that Phantauth allows to provision user or application directly via REST request which might be very useful when trying to build an automatic CI test scenario.

* [onlogin](https://www.onelogin.com/developer-signup): this is a real identity provider that supports far more than openid. It's developer account is simple to activate and the limitations are more than acceptable (3 applications and 25 users) which should be more than enough to start.

    see onelogin [kick-start](../idps/docs/onelogin-kickstart.html)

They are many other openid-connect authorities that proposes free developer accounts. Unfortunately we did not find application registration as intuitive as on github or onelogin.


## JWT
