# Canonical name: host-identify

> Historical private-repository rename record. This section describes the
> earlier in-place rename within the private development repository, **not**
> the new public `zog144/host-identify` created with fresh Git history.
> The public repository does not import that prior repository's commits/tags.

Historical rename checkpoint; see pyproject.toml and HOST-INSTALL.md for later versions.

The repository and Python distribution are now `zog144/host-identify` and
`host-identify`. Python imports use `zog.host_identify`. This follows Zog's program
naming convention. The GitHub repository was renamed in place, preserving its
repository ID and history. Subsequent work is published on unstable; main and
historical commits remain unchanged.

Install the exact new companion commits recorded by each consumer. The package
version remains 0.3.0: this is a coordinated source/package rename, so the version
string alone cannot distinguish old and new source sets. There is no runtime
`host_identity` compatibility alias. Existing environments keep working with their
old installed packages until explicitly upgraded; updating only one consumer
without its dependencies is not a supported migration.

The rename does not change signature components, replay semantics, enrollment
approval, archive token formats, subjects, audiences, filenames, private keys,
registry UUIDs or DNS ownership. Existing identities do not need regeneration or
approval merely because the Python package changed. No database migration is
required. Semantic terms such as HostIdentity, identity directories and the
existing HOST_IDENTITY_ORIGIN setting are protocol/domain concepts and remain
unchanged. Historical deployment evidence retains the name used at the time.

Host-deploy's source allowlist, package paths and SHA-256 hashes must come from the
coordinated consumer revision. Do not edit a deployed key directory, relabel an old
activation receipt, or use an old source pin with the renamed package directory.

Local package tests: 23 passed. All six runtime Python modules are byte-identical
to the original package; only their containing import-package directory changed.
This is local verification, not a live host upgrade or public release.
