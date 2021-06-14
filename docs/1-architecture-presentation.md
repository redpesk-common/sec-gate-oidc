# Introduction

afb-sec-gate-oidc is an afb-binder-v4 extension. It leverages binder hooking capabilities to enforce authentication from an external authority (IDP) to allow/deny HTTP/REST/WEBsocket requests.

Hooked input request can be checked again:

* LOA (Level Of Assurance) defines the level of trust you have in a given external authentication source. There is no standard to define LOA. Nevertheless most people loosely map it on NIST definition:

    * loa=0 public access
    * loa=1 basic authentication (just better than nothing)
    * loa=2 typical authentication (usually provided some trusted attributes as roles or groups.
    * loa=3 more trusted authentication (two factors ?)
    * loa=6 live critical authentication.

* Security attributes: allows to add fine grain access controls. They define a set of labels that should be provided by your IDP.

    * Enterprise IDPs typically provide either groups or roles.
    * github' provides organizations, repositories, ...
    * onelogin map groups on local roles or ldap/AD memberof request

    Each IDP has it own way to provide attributes. Idp security labels map to AFB-V4 privileged through an independant json configuration file, where security administrator may define a per IDP label/privilege mapping.

Typical access control:
``` json
 {"uid": "geoloc","uri":"unix:@gps-api", "loa":1, "require":["geoloc-role"]},
```

## workflow

sec-gate-oidc handshake relies on openid-connect specification. Any non openid authentication authority as to fake an official openid-c IDP. Social oAuh2 authority as github or Facebook are very close of OpenID require little customization, some other as PAM or LDAP require a specific adapter plugin.

To make a long story short:
* When user try to access a protected resource (loa > 0), sgate intercepts the request and check for current session LOA(Level of Assurance) and security attributes(groups/roles). When session does not hold enough privileges to access requested resource, sgate redirects client browser toward a list of configured IDPs that match resource requested LOA.

* User choose one IDP from propose list and sgate redirects client browser to selected authority login-page to retrieve an token-id access code. This redirect should include application client-id, requested scope, session state, ... and scope as well as client-id should match application configuration at remote authority side.

* Authority authenticates the user with a login/password challenge or any other authentication method it supports. When done it redirects client UI browser to the configured application redirect_uri with an access-token code matching requested application scope.

* sgate request through a REST back channel the authority 'authorize' end point to retrieve the [JWT(Json-Web-Token)](https://developer.yahoo.com/oauth2/guide/openid_connect/decode_id_token.html)
holding user identity attributes.

* sgate validate and retrieve user identity attributes from JWT and map them into client session social and federated User cookies. Then it check if this user is already known within current fedid-store.

* if user is unknown then sgate redirect client browser to globally configured registration page. After 1st authentication browser is directly redirected to requested resource.

Detail on OpenId-Connect specifications can be found [here](https://openid.net/developers/specs/)

**Note:**

* When the same user wish to authenticate from two different IDPs (i.e. office/home) then it should federates both social accounts. The sgate prevents a user with the same pseudo/email to register from two different authorities. When a user with the same pseudo/email try to register from a second authority he is automatically redirected to the federation page. In order to federate the user has to assert that he holds both social accounts credentials (login/password).

* LOA and security attributes. The LOA(Level Of Assurance) defines the level of trust you have in a given authentication. This LOA is statically defined within the configuration and user may choose which LOA fit with which IDP/profile. On the other the security attributes are dynamically provided by the IDP after the authentication, as a result it is possible to preselect an IDP because of requested LOA, but it is not possible to preselect an IDP that will match requested security attributes.


## Documentation

* [Installation Guide](./2-installation-guide.html)
* [Configuration](./3-configuration.html)
* [Secure Gateway SVC API](./4-sgate-svc-api.html)
* [Running and Testing](./5-running-and-testing.html)

## Support/sources

afb-sec-gate-oidc is part of redpesk-common and relies on [redpesk-core]({% chapter_link apis-services-doc.services-list %})

* Community support [#redpesk-core:matrix.org]( {% chapter_link community-doc.support %})
* source code: [github/redpesk-common](https://github.com/redpesk-common)

## HTML5 test page
![asset/sec-gate-oidc-archi](assets/sec-gate-oidc-archi.jpg)
