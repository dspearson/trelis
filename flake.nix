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

        # Nightly toolchain — covers stable features and adds Miri for UB detection
        rustToolchain = pkgs.rust-bin.nightly.latest.default.override {
          extensions = [ "rust-src" "rust-analyzer" "clippy" "rustfmt" "miri" ];
          targets = [ "wasm32-unknown-unknown" ];
        };

      in {
        devShells.default = pkgs.mkShell {
          buildInputs = with pkgs; [
            # Rust toolchain (nightly: superset of stable, required for Miri)
            rustToolchain
            cargo-watch
            cargo-edit
            cargo-audit
            cargo-outdated
            cargo-about
            cargo-deny
            cargo-geiger
            cargo-nextest
            cargo-tarpaulin
            cargo-bloat
            cargo-machete
            cargo-hack
            cargo-msrv

            # Coverage tools
            grcov
            lcov

            # Utilities
            just
            jq
            git
            direnv
          ];

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
            if ! cargo kani --version >/dev/null 2>&1; then
              echo "Installing cargo-kani (formal verification)..."
              cargo install --locked kani-verifier
            fi
          '';
        };

        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "trelis";
          version = "0.1.0";
          src = ./.;
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = false;
        };
      }
    );
}
