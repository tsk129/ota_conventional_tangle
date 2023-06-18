# iota.rs (iota-client)

The official, general-purpose IOTA client library in Rust for interaction with the IOTA network (Tangle).

The goal of this library is to have _one source code of truth_, which means that there is one implementation in Rust and [bindings](#bindings) to other programming languages.

For value transfers we recommend using [wallet.rs](https://github.com/iotaledger/wallet.rs).

This library allows you to do the following:

* Create messages with indexation and transaction payloads
* Get messages and outputs
* Sign transactions
* Generate addresses
* Interact with an IOTA node

## Branching structure for development

This library follows the following branching strategy:

|Branch|Description|
|------|-----------|
|`develop`|Ongoing development for future releases of the networks. This branch gets merged into `staging` on releases.|
|`legacy`|Deprecated, contains legacy releases supporting pre-Chrysalis features.|
|`production`|The latest releases for the IOTA networks.|
|`staging`|The latest releases for the Shimmer networks.|
| other |Other branches that may reflect current projects. Similar to `develop`, they will find their way into `staging` once they are ready.|

## Using the library

We recommend you to first update the Rust compiler to the latest stable version:

```shell
rustup update stable
```

The nightly Rust compiler should be fine but some changes might not be compatible.

Add `iota-client` as a dependency in `Cargo.toml`:

```toml
[dependencies]
iota-client = "1.4.0"
```

Or, for the latest changes:

```toml
[dependencies]
iota-client = { git = "https://github.com/iotaledger/iota.rs", branch = "production" }
```

Then, use the library in code with:

```rust
// Note that the hyphen is replaced with an underscore
use iota_client;
```

## Limitations

- `no_std` is not currently supported, but we are working on it in [bee](https://github.com/iotaledger/bee), and will provide it as feature once the new implementation is ready.
- When using the `mqtt` feature, connecting to a MQTT broker using raw IP doesn't work with TCP. This is a limitation of `rustls`.

## Examples

You can see examples using the library in the [examples](examples/) directory. Try them with:

```shell
# cargo run --example <name of the example without .rs>
cargo run --example 01_get_info
```

For examples where a seed is required (e.g. `03_generate_addresses`) you need to create a `.env` file under the current directory. You can do so by renaming [`.env.example`](.env.example) to `.env`.

## API reference

You can read the [API reference](https://docs.rs/iota-client) here, or generate it yourself.

If you'd like to explore the implementation in more depth, the following command generates docs for the whole crate, including private modules:

```shell
cargo doc --document-private-items --no-deps --open
```

## Bindings

Bindings to other programming languages are available under the folder [bindings](bindings/).

* [Node.js binding](bindings/nodejs/)
* [Python binding](bindings/python/)
* [Java binding](bindings/java/)
* [Wasm binding](bindings/wasm/)

## Joining the discussion

If you want to get involved in the community, need help with setting up, have any issues or just want to discuss IOTA with other people, feel free to join our [Discord](https://discord.iota.org/) in the #client-libraries and #client-discussion channels.

## License

The Apache 2.0 license can be found [here](LICENSE).
