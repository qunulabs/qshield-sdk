# qshield SDKs

Client libraries for [qshield](https://qnulabs.com), published from here.

| Language | Package | Directory |
| --- | --- | --- |
| TypeScript / Node | [`@qnulabs/qshield-sdk`](https://www.npmjs.com/package/@qnulabs/qshield-sdk) | [`js/`](./js) |

## Documentation

Documentation for the SDK lives in the qshield help centre, inside your own
deployment. This repository carries source and licence only.

## This repository is generated

Every file here is written by the qshield release pipeline from the private
monorepo where the SDKs are developed, reviewed and tested. Each release replaces
this tree wholesale, so a change committed here does not survive the next one.

Please raise issues and questions through your usual qshield support channel
rather than as pull requests.

## Why it exists

The SDKs are developed in the monorepo alongside the server they talk to, because
that is the only place the guards tying each client call to a real server route
can run. They are published from here because npm's credential-free publishing,
and the build provenance attached to every release, both require a public source
repository.

## Licence

Apache-2.0. See [`js/LICENSE`](./js/LICENSE).
