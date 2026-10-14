# host-identify public source and dependency notices

Original first-party Zog source and documentation in this repository are
licensed at your option under `BSD-3-Clause OR GPL-3.0-only`; see
[LICENSE](LICENSE) and both complete texts under [LICENSES](LICENSES/).

## Separately installed dependencies

The component declares http-message-signatures, cryptography, PyJWT, requests
and typing_extensions. Setuptools and pytest support building and testing.
None of these dependencies, nor their transitive dependencies, are vendored or
relicensed here. They retain their respective licenses and notices.

## Public source and historical evidence

The source snapshot contains synthetic test credentials and example host URLs,
not operational signing keys, bearer grants, identity directories or live
station records. Historical private Git commits, tags, handoff reports and
deployment evidence are excluded from this new public history. Historical
private revisions are not retroactively relicensed by this public grant.

The component is developed separately but distributed publicly through the
aggregate `zog` PyPI project assembled by release-build.
