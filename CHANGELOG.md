# Changelog

## [1.1.0](https://github.com/42-v/vault42/compare/v1.0.0...v1.1.0) (2026-02-21)


### Features

* add Helm chart for Vault42 deployment ([610c9fc](https://github.com/42-v/vault42/commit/610c9fc81cfa90ca5f42be848674fa0fa5096ef7))
* rebuild frontend as production-quality auth dashboard ([f1fc10a](https://github.com/42-v/vault42/commit/f1fc10a9eb034f361c0f3b931eefb5724f7de77c))


### Bug Fixes

* prevent panic in argon2 verify with malformed hash params ([9e7a784](https://github.com/42-v/vault42/commit/9e7a784a5618e38308074ea90fd954b9280aa229))
* resolve frontend tab switching, sessions display, and auth UX issues ([41bc765](https://github.com/42-v/vault42/commit/41bc765648d49fa340ee3e438ec86f7a4d56f141))
* restore multi-arch (amd64+arm64) to CI build step ([be4a579](https://github.com/42-v/vault42/commit/be4a5794e467197906c0346b7aae66fe59d82037))

## 1.0.0 (2026-02-21)


### Features

* add mandatory versioning with conventional commits ([9ced088](https://github.com/42-v/vault42/commit/9ced088bcaf2df28dd1be184c354590dc069c12e))
* auto-generate device friendly names and allow user rename ([a692251](https://github.com/42-v/vault42/commit/a6922518d60980021e3abe6c6ffd645c70861a31))


### Bug Fixes

* backup codes 500 error — add missing used_at column and replace DELETE with UPDATE ([bf9b954](https://github.com/42-v/vault42/commit/bf9b954bf6d2394a77b3d4eebc32abbbe9992905))
* session persistence and sessions view crash ([a08f786](https://github.com/42-v/vault42/commit/a08f786345b64200b6347327b3d26eed9a8d4c6a))


### Performance Improvements

* remove ARM from CI builds, simplify release to K8s-only ([9371d79](https://github.com/42-v/vault42/commit/9371d79caa4c1df1f145f4b6f326d1ce07ef580a))
