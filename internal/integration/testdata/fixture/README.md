# JavaScript fixture

`fixture.wasm` is generated from `fixture.js` with the Extism JavaScript PDK
compiler v1.7.0 and Binaryen 116:

```sh
extism-js fixture.js -i fixture.d.ts -o fixture.wasm
```

The official `extism-js-x86_64-linux-v1.7.0.gz` release artifact has SHA-256
`63b72da2f5e88655522dc21477de549f238a2f40546a69ce4e0fce7e78654035`.
Use the release matching the build host architecture.

The source is retained so the binary is reviewable and reproducible. The fixture
has successful, forbidden-network and non-terminating exports for runtime tests.
