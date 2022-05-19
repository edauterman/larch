# Testing

Before running any tests, make sure make sure your `ZOKRATES_HOME` environment variable is set correctly.
It has to point to `zokrates_stdlib/stdlib/`

## Unit tests
In ZoKrates, unit tests comprise
- internal tests for all zokrates crates
- compilation tests for all examples in `zokrates_cli/examples`. These tests only ensure that the examples compile.
- compilation + witness-computation tests. These tests compile the test cases, compute a witness and compare the result with a pre-defined expected result.
Such test cases exist for
    - The zokrates_core crate in `zokrates_core_test/tests`
    - The zokrates_stdlib crate in `zokrates_stdlib/tests`

Unit tests can be executed with the following command:

```
cargo test --release
```

## Integration tests

Integration tests are excluded from `cargo test` by default.
They are defined in the `zokrates_cli` crate in `integration.rs` and use the test cases specified in `zokrates_cli/tests/code`.

Before running integration tests:
1. Make sure your `$ZOKRATES_HOME` is set correctly 
2. You have [solc](https://github.com/ethereum/solc-js) installed and in your `$PATH`.

    Solc can conveniently be installed through `npm` by running 
    ```
    npm install -g solc
    ```
3. You have an Ethereum node running on localhost with a JSON-RPC interface on the default port 8545 (`http://localhost:8545`).

Integration tests can then be run with the following command:

```
cargo test --release -- --ignored
```
If you want to run unit and integrations tests together, run the following command:
```
cargo test --release & cargo test --release -- --ignored
```
