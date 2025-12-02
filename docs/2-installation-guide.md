# Installation

## Redpesk

`sec-gate-oidc` is part of redpesk-common and is available on any redpesk installation.

```bash
# on a target running redpesk OS
sudo dnf install sec-gate-oidc sec-gate-webui
```

## Other Linux Distributions

**Prerequisite**: should declare redpesk repository:
[[instructions-here]]({% chapter_link host-configuration-doc.setup-your-build-host %})

```bash
# Fedora
sudo dnf install sec-gate-oidc sec-gate-fedid-binding sec-gate-webui

# OpenSuse
sudo zypper install sec-gate-oidc sec-gate-fedid-binding sec-gate-webui

# Ubuntu
sudo apt-get install sec-gate-oidc-bin sec-gate-fedid-binding sec-gate-webui
```

Note:

* `sec-gate-webui`: is an optional angular/html5 frontend.
  If you do not use Angular, you should check basic HTML/JS testing UI and write your own one.

* `sec-gate-fedid-binding`: is the companion binding that handles the federation database.
  It implements locally an identity storage with a sqlite backend.
  The Identity store is implemented as an external binding to allow developers
  to replace it with their preferred identity store model.

# Quick test

## start sec-gate-oidc samples

Use one of the default config templates to write your own one and start
the binder with your own oidc-config.json

```bash
 # check with PAM login as fake IDP
 afb-binder --config=/my_config/oidc-local.json
```

**Note:** *any test with an external authority requires a minimum level of remote configuration.
Check specific IDPs requirement before trying oidc-oauth2.json samples.*

## Connect to HTML5 test page

Connect your browser to your sec-gate-oidc service with `https://target:port`
to display corresponding HTML5 test page.
When testing on your local machine redirect uri should look like
https://localhost:1234 when running sgate on a target,
then your should use https://target-ip-addr

* Note:

  * HTTPS requires SSL certificates.
    Check $PROJECT/data/ssl/gen-cert.sh to generated self signed SSL certificates.
    For development only, you may also choose to remove SSL.
    To remove SSL simply set 'HTTPS':false within your oidc-config.json

  * Warning: most IDPs impose HTTPS connection when using anything different from
    localhost as redirect login URL.

## Rebuild 'sec-gate-oidc' from sources

**Notice**: recompiling `sec-gate-oidc` is not required to implement your own set of rules.
You should recompile `sec-gate-oidc` when:

* targeting a not supported environment/distribution.
* changing code to fix bugs or propose improvements *(contributions are more than welcome)*
* adding custom/unsupported IDPs*

### Install building dependencies

#### Prerequisite

* declare redpesk repositories (see previous step).
* install typical Linux C/C++ development tool chain gcc+cmake+....

#### Install AFB binder and sec-gate-oidc dependencies

* application framework: 'afb-binding-devel', 'afb-binder-dev', 'afb-libafb-devel'
* cmake template 'afb-cmake-modules'

>Note: For Ubuntu/OpenSuse/Fedora specific instructions check
[redpesk-developer-guide]({% chapter_link host-configuration-doc.setup-your-build-host#install-the-application-framework-1 %})

#### Install sec-gate-oidc specific dependencies

* standard linux dependencies
  * cmake
  * make
  * gcc (or clang)
  * json-c
  * libpam-devel
  * libcurl-devel
  * uthash
  * pcsc-lite and pcsc-lite-libs

* Redpesk AFB application framework dependencies
  * afb-libafb-devel
  * rp-libutils-devel

>Note: all previous dependencies should be available out-of-the-box for major Linux
distributions (Fedora, OpenSuse, Ubuntu). Note that Debian/Ubuntu use '-dev' instead of '-devel'.

### Download source from git

```bash
    git clone https://github.com/redpesk-common/sec-gate-fedid-binding.git
    git clone https://github.com/redpesk-common/sec-gate-oidc.git
```

### Build your fedid binding and sgate binder extension

Build and install fedid-binding first, as the secure gate extension depends
on fedid types converters ship as part of fedid-binding.

Both should compile with standard AGL cmake template.

```bash
    mkdir build
    cd build
    cmake ..
    make
    make install
```

### Run a test from building tree

Create a custom config file from samples available at '../data/etc/oidc-\*.json'.
When config looks good try it with afb-binder --config.

Note that it is a good 'best-practice' to check your json config
with 'jq' on equivalent tools before trying to use it.

```bash
    jq < ../data/etc/my-oidc-config.json
    afb-binder --config=../data/etc/my-oidc-config.json -v
```

### Warning NFC USB reader (ACR122U) with pcscd

* Do not forget to update NFC kernel module blacklist

  * sudo cp $SOURCES/libs/pcscd-client/test/nfc-blacklist.conf /etc/modprobe.d

  * rmmod nfc and dependencies (or reboot)

  * systemctl enable pcscd.service

Check with you USB reader is visible with
```
    ./build/package/bin/pcscd-client --list
    -- reader[?]=ACS ACR122U PICC Interface 01 00
```

