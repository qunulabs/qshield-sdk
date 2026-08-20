# qshield SDKs

Client libraries for automating [qshield](https://qnulabs.com) from your own code.

| Language | Package | Source |
| --- | --- | --- |
| TypeScript / Node | [`@qnulabs/qshield-sdk`](https://www.npmjs.com/package/@qnulabs/qshield-sdk) | [`js/`](./js) |

## Install

```sh
npm install @qnulabs/qshield-sdk
```

Node 22 or later. **Server side only**: the SDK authenticates with a service-account
credential, which must never reach a browser. It has no runtime dependencies.

Every release is published with build provenance, so you can verify that the package you
installed was built from the source in this repository:

```sh
npm audit signatures
```

## Documentation

Full documentation lives in the help centre inside your own qshield deployment, alongside
the version you are running.

## Support

Please raise questions through your usual qshield support channel.

## Licence

Apache-2.0. See [`js/LICENSE`](./js/LICENSE).
