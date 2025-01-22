# tsndt
Tim's Secret Network Debugging Tool

Observe network information in your terminal! The goal of the tool is to allow operators to perform an initial deep-dive of network traffic on specific target systems. It is not intended to replace proper monitoring infrastructure.

## Demonstrations

Data is tracked on a per-network-interface basis. Network interface data collection can be toggled on and off to help improve performance and reduce clutter on the plots.

![Toggle network interfaces](https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExdjI1bDk4OGJkM2RwbXR6N29iYXVkYnF6M3VndnEyZ3B0MjN2cWo3MSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/35Sn1yGtaNWpOFDGoj/giphy.gif)

Plots can be resized so that the operator can focus on the data that they care about.

![Resize plots](https://media4.giphy.com/media/v1.Y2lkPTc5MGI3NjExY3VjaHM0MXdmNWIzbjBqd2l3MWFwNnNxeGNyZjAzbWdxOGNubHo1NSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/46mx4yblYumZsCB64u/giphy.gif)

By default, the vertical axis of the time series plots scales to allow observation of all of the data in the observation window. Users can optionally switch to a manual zoom mode to avoid dynamic axis changes on the time series plots at the risk of being unable to see some data points.

![Autoscaling and manual zoom](https://media2.giphy.com/media/v1.Y2lkPTc5MGI3NjExYXViazB5aHNoaWtnZXl2anJweDh4dml1Nmd4M3dyaW42NjhsMDlxeSZlcD12MV9pbnRlcm5hbF9naWZfYnlfaWQmY3Q9Zw/o2CFbM6iMUd3G5FmlO/giphy.gif)

## Prerequisites (for Aya)

1. stable rust toolchains: `rustup toolchain install stable`
1. nightly rust toolchains: `rustup toolchain install nightly --component rust-src`
1. (if cross-compiling) rustup target: `rustup target add ${ARCH}-unknown-linux-musl`
1. (if cross-compiling) LLVM: (e.g.) `brew install llvm` (on macOS)
1. (if cross-compiling) C toolchain: (e.g.) [`brew install filosottile/musl-cross/musl-cross`](https://github.com/FiloSottile/homebrew-musl-cross) (on macOS)
1. bpf-linker: `cargo install bpf-linker` (`--no-default-features` on macOS)

## Build & Run

Sudo privileges are required to run Aya because we want to load programs into the Kernel through eBPF.

Use `cargo build`, `cargo check`, etc. as normal. Run your program with:

```shell
cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

Cargo build scripts are used to automatically build the eBPF correctly and include it in the
program.

## Cross-compiling on macOS

Cross compilation should work on both Intel and Apple Silicon Macs.

```shell
CC=${ARCH}-linux-musl-gcc cargo build --package tsndt --release \
  --target=${ARCH}-unknown-linux-musl \
  --config=target.${ARCH}-unknown-linux-musl.linker=\"${ARCH}-linux-musl-gcc\"
```
The cross-compiled program `target/${ARCH}-unknown-linux-musl/release/tsndt` can be
copied to a Linux server or VM and run there.


## License

Copyright (c) Tim Upthegrove <tim.upthegrove@gmail.com>

This project is licensed under the MIT license ([LICENSE] or <http://opensource.org/licenses/MIT>)

[LICENSE]: ./LICENSE
