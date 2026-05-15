# Coverage Verification for vmrunner-macos-rs

## T073: Coverage Target - 80%+

This document explains how to verify code coverage for the vmrunner-macos-rs crate.

## Quick Start

```bash
# Run coverage check (terminal output)
cd admin/rust
./vmrunner-macos-rs/scripts/coverage.sh

# Generate HTML report
./vmrunner-macos-rs/scripts/coverage.sh --html

# Generate and open HTML report
./vmrunner-macos-rs/scripts/coverage.sh --open
```

## Tools

### cargo-tarpaulin

**Installation:**
```bash
cargo install cargo-tarpaulin
```

**Why tarpaulin?**
- Works with stable Rust (no instrumentation needed)
- Supports exclusion filters
- Generates HTML and terminal reports
- CI-friendly output

### Alternative: cargo-llvm-cov

If tarpaulin has issues, `cargo-llvm-cov` is an alternative:

```bash
cargo install cargo-llvm-cov

# Run coverage
cargo llvm-cov --package vmrunner-macos-rs --html

# Open report
cargo llvm-cov --package vmrunner-macos-rs --open
```

## Current Coverage

As of latest run:

| Module | Coverage | Status |
|--------|----------|--------|
| `src/lib.rs` | TBD | ⏳ |
| `src/vz.rs` | TBD | ⏳ |
| `src/config.rs` | TBD | ⏳ |
| `src/snapshot.rs` | TBD | ⏳ |
| `src/network.rs` | TBD | ⏳ |
| `src/error.rs` | TBD | ⏳ |
| `src/warm_pool.rs` | TBD | ⏳ |
| **Overall** | **TBD** | ⏳ |

## Target

**80%+ coverage** for vmrunner-macos-rs (NFR-017)

This ensures:
- Core functionality is well-tested
- Edge cases are covered
- Unsafe Rust blocks are validated

## Exclusions

The following are excluded from coverage:

1. **Test files**: `tests/` directory
2. **Benchmark files**: `benches/` directory
3. **Binary crates**: `src/bin/` directory
4. **Integration tests**: Files that require real VZ Framework

## CI Integration

Coverage is checked in CI via `.github/workflows/macos-performance.yml`.

To add coverage to your CI:

```yaml
- name: Run coverage check
  run: |
    ./vmrunner-macos-rs/scripts/coverage.sh
```

## Improving Coverage

### Find Uncovered Code

1. Generate HTML report:
   ```bash
   ./scripts/coverage.sh --html
   ```

2. Open `target/coverage/index.html`

3. Look for red lines (uncovered code)

4. Add tests for uncovered paths

### Common Gaps

- **Error handling**: Add tests for error cases
- **Edge cases**: Boundary values, empty inputs
- **Async operations**: Success and failure paths
- **Unsafe blocks**: Verify safety invariants

## Coverage Badges

To add a coverage badge to README.md:

```markdown
[![Coverage](https://img.shields.io/badge/coverage-80%25-brightgreen.svg)]
```

Update the percentage with actual coverage from tarpaulin output.

## Troubleshooting

### tarpaulin fails to build

**Issue**: Compilation errors during coverage

**Solution**:
```bash
# Clean build
cargo clean

# Run coverage with more verbose output
RUST_LOG=error cargo tarpaulin --package vmrunner-macos-rs --verbose
```

### Slow coverage run

**Issue**: Coverage takes too long

**Solution**: Reduce test count or use `--test-threads=1`:
```bash
cargo tarpaulin --package vmrunner-macos-rs -- --test-threads=1
```

### Missing line coverage

**Issue**: Some lines not covered

**Solution**: Check if:
1. Code is platform-specific (`cfg(target_os = "macos")`)
2. Code is dead (unreachable)
3. Tests don't exercise that path

For platform-specific code, coverage may be lower than 80% - this is acceptable.

## Continuous Monitoring

Coverage should be checked:

1. **Before commits**: Run `./scripts/coverage.sh`
2. **In PRs**: CI runs coverage automatically
3. **After refactor**: Verify coverage didn't drop

## References

- [tarpaulin documentation](https://github.com/xd009642/tarpaulin)
