# Configuration

## afb-sgate AFB binder config

sgate relies the new V4 afb-binder config file.  *It is highly recommended to check your config.json with a json linter after any modification.*

```bash
# check config.json validity with JQ
jq < oidc-config.json
```

### Binder standard config

The initial part of oidc-config.json is not specific to the secure-gateway and is common for any afb-binder V4. It configure basic afb-binder options as port,ssl,rootdir,...

```json
{
  "name": "afb-oidc",
  "verbose": 2,
  "port": 1234,
  "https": true,
  "https-cert": "../conf.d/project/ssl/devel-cert.pem",
  "https-key": "../conf.d/project/ssl/devel-key.pem",
  "extension": "./package/lib/afb-sgate.extso",
  "rootdir":  "../conf.d/project/htdocs",
  "roothttp": ".",
}
```

### FedID companion binding

FedID-binding provides the identity federation API. It is designed as a replaceable component, also you may choose to replace it with your own version of it. Current implementation should share the same afb-binder as the sgate extension. This constrain might be remove on future versions of the extension.

FedID-binding is a native afb-V4 binding, it configuration only required the path to the fedid-sqllite.db file. When no configuration is provided default path is /var/tmp/fedid-sqllite.db

```json
"binding" : [
  {"uid": "fedid-api",
   "path": "/usr/local/fedid-binding/lib/fedid-binding.so",
   "config": {"dbpath":"/var/store/fedid-sqllite.db"}
  }
],
```

*Note*:

* At init time, fedid check for sqllite.db file. If not present it creates an empty DB with corresponding fedid schema. As a result during develop phase developer may safely delete the sqllite.db and restart test from a fresh empty identity federation data store.

* FedID binding provides AFB-V4 type converters. Those converters are share in between sgate extension and FedID binding. They are implemented as an independent sharelib that is shipped with FedID but require by the sgate extension.

For futher information on AFB-v4 types check [redpesk-documentation](https://docs.redpesk.bzh/docs/en/master/developer-guides/reference-v4/types-and-globals.html)

### sgate extension

sgate is not a binding, but a binder-v4 extension. As a result it has access to every internal API from the binder and is not bound to any security restriction as a normal binding. Technically the extension implement hook on defined API/URL and intercept the incoming request to check if authentication level is acceptable or not.

### Configuration is split into sections:

* **global**: defines  default URL and global session timeout
* **idps**: one configuration per IDP (authentication authority)
* **apis**: imported API exposure and access control for REST/WEBsocket
* **alias**: HTTP access control.

### Global section
Define where user should be redirected when hitting a protected resource. Note that when WebSocket is used the same information is provided to client UI as an event in place of a traditional HTTP redirect.

```json
"@extconfig": {
    "sgate": {
      "api": "sgate",
      "info": "oidc secure gateway demo config",
      "globals": {
          "info" : "some misc useful info",
          "login": "/sgate/common/login.html",
          "register": "/sgate/common/register.html",
          "federate": "/sgate/common/fedlink.html",
          "home": "/",
          "error": "/sgate/common/error.html",
          "timeout": 600,
          "cache": 5000,
      },
    }
}
```
* **api**: name of the sgate api as view from external application.
* **login**: redirect URL where application are redirected when an authentication is not strong enough. This page should present to end user and IDP selection list.
* **register**:  redirect URL when on first authentication of a given user from a given authority. This page should request some basic user attributes as pseudo and email.
* **fedlink**: redirect URL to link two external identities to a unique local identity.
* **timeout**: global default timeout session in seconds. Defined how often an authority authentication token should be rechecked (from last authentication time and not from HTTP/REST request). Default:600s
* **cache**: default access control list cache in ms. Defined how often access control should be recheck for a given Alias/API. Default: 5000ms

### IDP section
A json array defining each authentication authority. Default authority are oAith2/OpenID-connect compliant. Nevertheless is is possible to add custom local/remote authority (check pam plugin as sample).

```json
{
    "uid": "onelogin",
    "type": "oidc",
    "info": "Free OpenIdC testing authority (http://onelogin.com)",
    "credentials": {
      "clientid": "---my-client-app--id----",
      "secret": "---my-client-app-secret---",
    },
    "wellknown": {
        "discovery": "https://iot-bzh-dev.onelogin.com/oidc/2/.well-known/openid-configuration"
    },
    "statics": {
        "login": "/sgate/onelogin/login",
        "logo": "/sgate/onelogin/logo-64px.png",
        "timeout": 600
    },
    "profiles": [
        {"uid":"basic", "loa":1, "scope":"user:email"},
        {"uid":"teams", "loa":2, "scope":"read:org", "label":"organizations_url"}
    ]
}
```
* **uid**: IDP unique label
* **type**: define buildin/plugin idp code to be used, when not defined type=uid.
* **info**: Misc text presented with IDP list page
* **credentials**: This information should be provided from your external authority. OpenID-Connect typically require a ClientID and a Secret, but depending on the IDP you may have other form of credential. You may check OpenID-Connect generic protocol [here](https://openid.net/connect)  and onelogin specifics [here](https://docs.onelogin.com/en/developers/apps/authorizing-oauth-apps)

* **wellknown**: remote IDP authority URLs. Following URL/URI should be available without your IDP administration console, as here after:
![onelogin-discovery-uri](./asset/onelogin-discovery.png)

    * **discovery**: remote IDP authority URLs, typically one URL to request the initial authentication token, then an other one to request the access token and final as many as needed URL for identity services provided by the authority. For further info about discovery check [openid-discovery-spec](https://openid.net/specs/openid-connect-discovery-1_0.html)

        When available wellknown URI will be query as sgate startup time and will automatically populate all following parameters. *Note that wellknown URI is require by openid-connect specification. Using a static definition in place of wellknown may save few seconds at sgate service startup time.*

      * **tokenid**: HTTP page to retrieve authentication tokenid code. When an authentication is require, the sgate redirects client UI to this URL. Then if needed the authority prompts user for authentication, in all the other case authority should automatically redirect back sgate in SSO(Single-Sign-On). When authentication is successful IDP redirects back client UI to the secure gateway 'login' alias defined later within the 'statics' section of your oidc-config.json

      * **authorize**: REST exchange authentication end-point. Provided an access-token from the authentication tokenid received from 'tokenid' SSO. The request to 'authorize' does not go through user browser, this avoid to expose IDP application secret to user browser.

      * **userinfo**: REST authority identity service. Provide identity attributes matching requesting scope. Note that some authority as onelogin has multiple identity end point depending requested attributes.

* **statics**: define the REST/HTTP end point created by the secure-gateway for IDPs protocol handshake.

  * **login**: this is where remote IDP should redirect user after a valid HTTP authentication. When this page is called without a valid code from the authority user HTML application is redirect back to corresponding authority.
  * **logout**: where IDP should post a back-channel logout when user session timeout. For further information about global logout check [openid-logout-spec](https://openid.net/specs/openid-connect-backchannel-1_0.html)
  * **logo**: misc information provided to login page when list available IDPs.
  * **timeout**: default timeout for this specific IDPs. After this timeout IDP LOA is reset to zero which force a token renewal negotiation.

* **profile**: each authority may support multiple [scope](https://auth0.com/docs/scopes/openid-connect-scopes) of authentication. A given scope typically imply a different authentication method (e.g. single vs double factor) and provide access to different user identity attributes. Scopes depend on IDP, most of them propose a, 'email' scope that typically respond to a basic LOA=1 model.

  * **uid**: unique profile label
  * **loa**: level of assurance attached to this IDP profile
  * **scope**: scope request when requesting authentication
  * **label**: custom IDP label. It is used to request further identity information from IDP services. In the case of github 'organizations_url' is the json key used to return organizations a user belows to.

### API section

list of binding APIs that sgate should make visible to external clients as with '--ws-client' binder command line argument. When a requested privileges is not present sgate redirect client browser to login page. Note that WebSocket does not support redirect, when a websocket request is refused the application only receive an "UNAUTHORIZED" error status. User application should subscribe to sgate events to be notified of refusal/error messages.

API is a json array, that at minimum contains the API name to import and expose. Technically defining API here is somehow equivalent to use afb-binder --ws-client argument.


```json
"apis": [
    {"uid": "api_1"},
    {"uid": "api_2","uri":"unix:@api_2", "loa":1, "require": ["user"], "lazy":1},
    {"uid": "api_3"","uri":"tcp:localhost:1235/api_name", "loa":2, "require": ["user","admin"], "lazy":1},
    {"uid": "api_xxx","uri":"unix:/tmp/spawn-binding/sample", "loa":1, "require": ["user"], "lazy":1}
    {"uid": "fedid","info":"internal federated ID service","loa":3,"uri":"@fedid", "require":"admin"},
],
```

  * **uid**: api name as exported on sgate external interface.
  * **info**: misc user info presented to application then an authentication is required.
  * **loa**: level of assurance requested to access this page. By depend any IDP with equal or greater LOA will let the request go thought. When LOA is negative then the IDP should exactly request LOA. This is a very simple model to force a specific IDP on a give set of resources.
  * **require**: a list of either/or security labels check again identity authority. This list vary from one IDP to an other. Warning: this list is a logical OR, one match is enough to pass the check.
  * **prio**: access control priority list. The highest number being check first. Priority key might be use to implement complex access control as local AND case for security attributes.
  * **uri**: which API to import. The "@api_name is the preferred method to import API from bindings running on the same Linux instance, to import API from binding running on the remote Linux instance use 'tcp:hostname:port/api' as with the --ws-client afb-binding command line option.
  * **lazy**: when true sgate will start even if API to import is not present.

### Alias section

Like API section but for HTTP request. Alias array is somehow equivalent to an afb-binder --alias arguments that would have privilege requirement. When a user try to access an alias without enough privileges his browser is redirect to corresponding login page.

```json
"alias": [
        {"uid": "idp-common", "url":"/sgate/common", "path":"idps/common" },
        {"uid": "idp-onelogin" , "url":"/sgate/onelogin"   ,"loa":0, "path":"idps/onelogin" },
        {"uid": "public" , "info": "Anonymous access allowed", "url":"/public", "path":"public" },
        {"uid": "private", "info": "Required basic authentication", "url":"/private",  "loa":1, "path":"private" },
        {"uid": "confidential", "info": "Required teams authentication", "url":"/confidential", "loa":2, "path":"confidential", "require": ["admin"] },
        {"uid
```


  * **uid**: alias name as exported on sgate external interface.
  * **info**: misc user info presented to application then an authentication is required.
  * **loa**: level of assurance requested to access this page.
  * **require**: a logical 'OR' list of requested IDP attributes. Note that you usually do not control IDP group/roles attributes and when supporting multiple auhtority you may have two names for the same privilege.
  * **prio**: access control priority list. Priority is an option to implement logical AND access control. The highest priority is executed first and all rules should pass for access to be granted to requesting client.
