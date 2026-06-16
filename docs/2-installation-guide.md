# Installation

## From package

You can run the same command on a target runing a redpesk OS or in the [SDK container]({% chapter_link sdk-container-doc.overview %}) (development mode).

```bash
dnf install sec-gate-oidc sec-gate-fedid-binding sec-gate-webui
```

## From sources

When developing inside the SDK container, to install the build dependencies, run the following command:

```bash
dnf builddep sec-gate-oidc sec-gate-fedid-binding sec-gate-webui
```

Then clone and build from sources.

```bash
    git clone https://github.com/redpesk-common/sec-gate-fedid-binding.git
    git clone https://github.com/redpesk-common/sec-gate-oidc.git
```

Build and install fedid-binding first, as the secure gate extension depends
on fedid types converters ship as part of fedid-binding.

```bash
    mkdir build
    cd build
    cmake ..
    make
```

> Note: To rebuild all (including application framework) from sources, please refer to this [chapter]({% chapter_link host-build-doc.build-framework-on-your-computer %}).
