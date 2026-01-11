{
  description = "Trelis - Hybrid Post-Quantum Cryptographic Library";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs = { self, nixpkgs, flake-utils, rust-overlay }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        overlays = [ (import rust-overlay) ];
        pkgs = import nixpkgs {
          inherit system overlays;
        };

        # Rust toolchain (stable, requires 1.85+ for edition 2024)
        rustToolchain = pkgs.rust-bin.stable.latest.minimal.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" ];
          targets = [ "wasm32-unknown-unknown" ];
        };

      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain (1.85+ for edition 2024)
            rustToolchain
            cargo-watch
            cargo-edit
            cargo-audit
            cargo-outdated
            cargo-about
            cargo-deny
            cargo-nextest
            cargo-tarpaulin
            cargo-bloat
            cargo-machete
            cargo-hack
            cargo-msrv

            # Build dependencies for pqcrypto-ntruprime (C FFI)
            clang
            llvmPackages.libclang
            pkg-config

            # Coverage tools
            grcov
            lcov

            # Utilities
            just
            jq
            git
            direnv
          ];

          # Required for pqcrypto C bindings
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";

          shellHook = ''
            # Rust environment
            export RUST_BACKTRACE=1
            export RUST_LOG="debug"

            echo ""
            echo "Trelis Development Environment"
            echo ""
            echo "  just build   - Build all crates"
            echo "  just test    - Run all tests"
            echo "  just lint    - Run clippy"
            echo "  just fmt     - Format code"
            echo ""
            echo "Rust: $(rustc --version)"
            echo ""
          '';
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "trelis";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          nativeBuildInputs = with pkgs; [ pkg-config clang ];
          LIBCLANG_PATH = "${pkgs.llvmPackages.libclang.lib}/lib";
          doCheck = false;
        };
      }
    );
}
