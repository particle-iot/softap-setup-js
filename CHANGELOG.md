# changelog

## 4.0.2 - 15 Feb 2017

* [#17](https://github.com/spark/softap-setup-js/pull/17) change license from LGPL to Apache 2.0
* [#13](https://github.com/spark/softap-setup-js/pull/13) default timeout increase from 2s to 8s for TCP
* [#13](https://github.com/spark/softap-setup-js/pull/13) TCP response can be spread over multiple packets
* [#24](https://github.com/spark/softap-setup-js/issues/24) Configuration defaults move into SoftAP class so they are available for TCP and HTTP
* [#18](https://github.com/spark/softap-setup-js/issues/18) Device ID change to lowercase
* [#23](https://github.com/spark/softap-setup-js/issues/23) deviceInfo request was failing with timeout


## 4.0.1 - 26 Feb 2016

* Explicitly specify 'http' as protocol

## 4.0.0 - 23 Feb 2016

* Remove environment variable and file configuration options.
* Rename `keep_alive` to `keepAlive` and `no_delay` to `noDelay`.
* Implement a strict timeout.
* Improve error handling.

## 3.0.2 - 15 Oct 2015

* Include bugfix by indraastra for CORS requests without preflights.
