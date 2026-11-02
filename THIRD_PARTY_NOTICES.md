# Third-party sources

## jiatj/wechatapi — Apache-2.0

Source: https://github.com/jiatj/wechatapi/blob/04ef8cbde3862cff90b5f6b42c9ebfcea44ef48d/wechatauto/db.py

`scripts/vendor/keyscan.py` extracts the read-only Config.Cipher scanner from this revision. Modified to isolate scanning, remove persistent key caches and unrelated database/UI methods, and declare Windows HANDLE cleanup signatures. Original license is reproduced in the repository `LICENSE`. No NOTICE file was present in the source checkout.

## tzwkb/wechat-decrypt — MIT

Source revision: https://github.com/tzwkb/wechat-decrypt/tree/f0b3f9f95dda2d954ee3dbe1d139fb1944a5ecfd

`scripts/vendor/appmsg.py` and `scripts/vendor/wal_snapshot.py` are copied from this revision without functional changes. The MIT license and copyright notice are reproduced at `scripts/vendor/MIT_LICENSE`.

The main workflow, packaging, formatter integration, safeguards and tests are provided under Apache-2.0. Runtime dependencies retain their respective licenses and are installed separately; no dependency binaries or account data are bundled.
