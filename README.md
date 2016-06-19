# HTTP Public-Key-Pinning Builder

[![Build Status](https://travis-ci.org/paragonie/hpkp-builder.svg?branch=master)](https://travis-ci.org/paragonie/hpkp-builder)

This library aims to make it easy to build HTTP Public-Key-Pinning headers
in your PHP projects. HPKP Builder was  was created by
[Paragon Initiative Enterprises](https://paragonie.com) as part of our effort
to encourage better [application security](https://paragonie.com/service/appsec)
practices.

Check out our other [open source projects](https://paragonie.com/projects) too.

## PHP Version requirements

* PHP 7.0 or newer

## Build a Public-Key-Pinning header from a JSON configuration file

```php
<?php

use \ParagonIE\HPKPBuilder\HPKPBuilder;

$hpkp = HPKPBuilder::fromFile('/path/to/source.json');
$hpkp->sendHPKPHeader();
```
### Example JSON configuration

```json
{
    "hashes": [
        {
            "algo": "sha256",
            "hash": "hwGEkxDWJ2oHtKv6lsvylKvhotXAAZQR1e0nq0eb2Vw="
        },
        {
            "algo": "sha256",
            "hash": "0jum0Eiu4Eg6vjn3zTmyd/RobfN6e4EagFQcz6E5ZKI="
        }
    ],
    "include-subdomains": false,
    "max-age": 5184000,
    "report-only": false,
    "report-uri": null
}
```

## Build a Public-Key-Pinning Header

```php
<?php

use \ParagonIE\HPKPBuilder\HPKPBuilder;

$hpkp = (new HPKPBuilder)
    ->addHash('hwGEkxDWJ2oHtKv6lsvylKvhotXAAZQR1e0nq0eb2Vw=')
    ->addHash('0jum0Eiu4Eg6vjn3zTmyd/RobfN6e4EagFQcz6E5ZKI=')
    ->addHash('JDR7yv7lvdKaM26fnKriSPiyryeYw9qi5sO8Ot7SNUQ=')
    ->includeSubdomains(true)
    ->reportOnly(true)
    ->reportUri('https://report-uri.io')
    ->sendHPKPHeader();
```
