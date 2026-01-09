# Trelis - Hybrid Post-Quantum Cryptographic Library
# Use `just --list` to see all available commands

# Default recipe (runs when you just type `just`)
default:
    @just --list

# ============================================
# Build Commands
# ============================================

# Build all workspace crates
build:
    cargo build --workspace

# Build with release optimisations
build-release:
    cargo build --workspace --release

# Build a specific crate
build-crate crate:
    cargo build -p {{crate}}

# Build error handling crate
build-error:
    cargo build -p trelis-error

# Build cryptographic primitives
build-primitives:
    cargo build -p trelis-primitives

# Build hybrid key encapsulation
build-hybrid:
    cargo build -p trelis-hybrid

# Build wire format serialisation
build-wire:
    cargo build -p trelis-wire

# Build post-quantum X3DH
build-x3dh:
    cargo build -p trelis-x3dh-pq

# Build double ratchet
build-ratchet:
    cargo build -p trelis-ratchet

# Build COCOA group messaging
build-cocoa:
    cargo build -p trelis-cocoa

# Build multi-device support
build-multidevice:
    cargo build -p trelis-multidevice

# Build WebAssembly bindings
build-wasm:
    cargo build -p trelis-wasm --target wasm32-unknown-unknown

# ============================================
# Test Commands
# ============================================

# Run all tests (including ignored/stress tests)
test:
    cargo test --workspace -- --include-ignored

# Run tests with output (including ignored/stress tests)
test-verbose:
    cargo test --workspace -- --include-ignored --nocapture

# Run tests quickly (skips stress tests)
test-fast:
    cargo test --workspace

# Run tests for a specific crate
test-crate crate:
    cargo test -p {{crate}}

# Run tests with nextest (faster, parallel)
test-nextest:
    cargo nextest run --workspace

# Watch and run tests on changes
watch-test:
    cargo watch -x "test --workspace"

# Run tests with all feature combinations
test-features:
    cargo hack test --workspace --feature-powerset

# Run doc tests only
test-doc:
    cargo test --workspace --doc

# ============================================
# Code Coverage
# ============================================

# Generate code coverage report with tarpaulin (HTML)
coverage:
    cargo tarpaulin --workspace --out Html --output-dir coverage
    @echo "Coverage report: coverage/tarpaulin-report.html"

# Generate code coverage report (XML for CI)
coverage-xml:
    cargo tarpaulin --workspace --out Xml --output-dir coverage

# Generate code coverage report (Lcov format)
coverage-lcov:
    cargo tarpaulin --workspace --out Lcov --output-dir coverage

# Generate coverage for a specific crate
coverage-crate crate:
    cargo tarpaulin -p {{crate}} --out Html --output-dir coverage

# Quick coverage summary (no HTML)
coverage-summary:
    cargo tarpaulin --workspace --skip-clean

# Generate LLVM coverage (alternative to tarpaulin)
coverage-llvm:
    #!/usr/bin/env bash
    set -euo pipefail
    RUSTFLAGS="-C instrument-coverage" cargo test --workspace
    grcov . -s . --binary-path ./target/debug/ -t html --branch --ignore-not-existing -o ./coverage-llvm
    @echo "LLVM coverage report: coverage-llvm/index.html"

# ============================================
# Quality Commands
# ============================================

# Check code (fast, no codegen)
check:
    cargo check --workspace

# Run clippy linter
lint:
    cargo clippy --workspace -- -D warnings

# Run clippy with all targets
lint-all:
    cargo clippy --workspace --all-targets -- -D warnings

# Run clippy and fix issues automatically
lint-fix:
    cargo clippy --workspace --fix --allow-dirty --allow-staged

# Format code
fmt:
    cargo fmt --all

# Check formatting
fmt-check:
    cargo fmt --all -- --check

# Run security audit
audit:
    cargo audit

# Fix known vulnerabilities where possible
audit-fix:
    cargo audit fix

# Check for outdated dependencies
outdated:
    cargo outdated

# Check for outdated dependencies (root only)
outdated-root:
    cargo outdated --root-deps-only

# Update dependencies
update:
    cargo update

# Update a specific dependency
update-crate crate:
    cargo update -p {{crate}}

# ============================================
# Dependency Analysis
# ============================================

# Show crate dependency tree
tree:
    cargo tree --workspace

# Show dependency tree for a specific crate
tree-crate crate:
    cargo tree -p {{crate}}

# Show reverse dependencies (what depends on a crate)
tree-invert crate:
    cargo tree -i {{crate}}

# Show duplicate dependencies
tree-duplicates:
    cargo tree --workspace --duplicates

# Find unused dependencies
unused-deps:
    cargo machete

# Check for yanked dependencies
check-yanked:
    cargo deny check advisories

# ============================================
# Binary Analysis
# ============================================

# Analyse binary bloat (requires release build)
bloat:
    cargo bloat --release --workspace

# Analyse binary bloat by crate
bloat-crates:
    cargo bloat --release --workspace --crates

# Show binary size breakdown
bloat-time:
    cargo bloat --release --workspace --time

# ============================================
# Safety & Correctness
# ============================================

# Run Miri to detect undefined behaviour
miri:
    cargo +nightly miri test --workspace

# Run Miri on a specific crate
miri-crate crate:
    cargo +nightly miri test -p {{crate}}

# Check minimum supported Rust version
msrv:
    cargo msrv --workspace

# Verify MSRV is correct
msrv-verify:
    cargo msrv verify

# ============================================
# Documentation
# ============================================

# Generate and open documentation
docs:
    cargo doc --workspace --no-deps --open

# Generate documentation without opening
docs-build:
    cargo doc --workspace --no-deps

# Generate docs with private items visible
docs-private:
    cargo doc --workspace --no-deps --document-private-items --open

# Check documentation coverage
docs-coverage:
    RUSTDOCFLAGS="-Z unstable-options --show-coverage" cargo +nightly doc --workspace --no-deps

# Check for broken documentation links
docs-check:
    cargo doc --workspace --no-deps 2>&1 | grep -E "(warning|error)" || echo "No documentation warnings"

# ============================================
# Watch Commands
# ============================================

# Watch and rebuild on changes
watch:
    cargo watch -x "build --workspace"

# Watch and check on changes
watch-check:
    cargo watch -x "check --workspace"

# Watch and lint on changes
watch-lint:
    cargo watch -x "clippy --workspace"

# Watch a specific crate
watch-crate crate:
    cargo watch -x "build -p {{crate}}"

# ============================================
# Maintenance
# ============================================

# Clean build artifacts
clean:
    cargo clean

# Clean and rebuild
rebuild: clean build

# Full CI check (what CI runs)
ci: fmt-check lint test
    @echo "All CI checks passed!"

# Extended CI check (includes more checks)
ci-full: fmt-check lint-all test audit outdated
    @echo "All extended CI checks passed!"

# Development workflow: format, check, test
dev: fmt check test
    @echo "Development checks passed!"

# Pre-commit check (fast)
pre-commit: fmt-check check lint
    @echo "Pre-commit checks passed!"

# Run benchmarks
bench:
    cargo bench --workspace

# Run benchmarks for a specific crate
bench-crate crate:
    cargo bench -p {{crate}}

# ============================================
# Release Preparation
# ============================================

# Full release check
release-check: ci-full coverage docs-build
    @echo "Release checks passed!"

# Dry-run publish
publish-dry-run crate:
    cargo publish -p {{crate}} --dry-run

# Verify package contents
package-list crate:
    cargo package -p {{crate}} --list

# ============================================
# Environment Info
# ============================================

# Show environment info
info:
    @echo "Trelis Development Environment"
    @echo "==============================="
    @echo ""
    @echo "Workspace crates:"
    @echo "  trelis-error       - Error types and handling"
    @echo "  trelis-primitives  - Ed448, ML-DSA, NTRU Prime"
    @echo "  trelis-hybrid      - Hybrid key encapsulation"
    @echo "  trelis-wire        - Wire format serialisation"
    @echo "  trelis-x3dh-pq     - Post-quantum X3DH"
    @echo "  trelis-ratchet     - Double ratchet protocol"
    @echo "  trelis-cocoa       - CoCoA-SA group messaging"
    @echo "  trelis-multidevice - Multi-device support"
    @echo "  trelis-wasm        - WebAssembly bindings"
    @echo ""
    @echo "Toolchain:"
    @echo -n "  Rust: " && rustc --version
    @echo -n "  Cargo: " && cargo --version
    @echo ""

# Show installed cargo tools
tools:
    @echo "Installed cargo tools:"
    @which cargo-watch >/dev/null 2>&1 && echo "  cargo-watch" || echo "  cargo-watch (missing)"
    @which cargo-nextest >/dev/null 2>&1 && echo "  cargo-nextest" || echo "  cargo-nextest (missing)"
    @which cargo-tarpaulin >/dev/null 2>&1 && echo "  cargo-tarpaulin" || echo "  cargo-tarpaulin (missing)"
    @which cargo-audit >/dev/null 2>&1 && echo "  cargo-audit" || echo "  cargo-audit (missing)"
    @which cargo-outdated >/dev/null 2>&1 && echo "  cargo-outdated" || echo "  cargo-outdated (missing)"
    @which cargo-bloat >/dev/null 2>&1 && echo "  cargo-bloat" || echo "  cargo-bloat (missing)"
    @which cargo-machete >/dev/null 2>&1 && echo "  cargo-machete" || echo "  cargo-machete (missing)"
    @which cargo-deny >/dev/null 2>&1 && echo "  cargo-deny" || echo "  cargo-deny (missing)"
    @which cargo-hack >/dev/null 2>&1 && echo "  cargo-hack" || echo "  cargo-hack (missing)"
    @which cargo-about >/dev/null 2>&1 && echo "  cargo-about" || echo "  cargo-about (missing)"

# ============================================
# Licence Management
# ============================================

# Generate 3RD-PARTY-LICENCES.md from all dependencies
licences:
    @echo "Generating third-party licence file..."
    cargo about generate about.hbs -o 3RD-PARTY-LICENCES.md
    @echo "Generated 3RD-PARTY-LICENCES.md"

# Check licences for compliance
licences-check:
    @echo "Checking licence compliance..."
    cargo deny check licenses

# List all dependency licences
licences-list:
    cargo tree --workspace --format "{p} {l}" --prefix none | sort -u
