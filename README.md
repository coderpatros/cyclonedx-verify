# CycloneDX Integrity Verification

A command-line tool that verifies the integrity of [CycloneDX](https://cyclonedx.org/) Software Bill of Materials (SBOM) files in JSON format. It checks that:

1. **Signatures** are valid (JSF signature verification)
2. **File hashes** match what the SBOM declares
3. **No untracked files** exist in the target directory that aren't accounted for in the SBOM

## Usage

```
cdx-verify <sbom-file> [options]
```

### Arguments

| Argument | Description |
|---|---|
| `sbom-file` | Path to the CycloneDX SBOM JSON file |

### Options

| Option | Description |
|---|---|
| `--base-dir <dir>` | Base directory for resolving component file paths (default: current directory) |
| `--key-file <file>` | Path to a JWK public key file for signature verification |
| `--allow-embedded-key` | Allow embedded public keys in JSF signatures |
| `--ignore <pattern>` | Ant path patterns for files/directories to exclude from untracked file detection (repeatable) |

### Examples

```bash
# Basic verification
cdx-verify sbom.json

# Verify against a specific directory with a signing key
cdx-verify sbom.json --base-dir /path/to/files --key-file public.jwk

# Ignore build artifacts and log files
cdx-verify sbom.json --ignore "build/**" --ignore "**/*.log"
```

### Example output

```
$ ./cdx-verify bom.json --ignore bom.*
=== Signature Verification ===
[SKIP] No signature found in SBOM. Skipping signature verification.

=== Hash Verification ===
[PASS]     cdx-verify [SHA_256]
[PASS]     cdx-verify.deps.json [SHA_256]
[PASS]     cdx-verify.dll [SHA_256]
[PASS]     cdx-verify.pdb [SHA_256]
[PASS]     cdx-verify.runtimeconfig.json [SHA_256]
[PASS]     BouncyCastle.Cryptography.dll [SHA_256]
[PASS]     AntPathMatching.dll [SHA_256]
[PASS]     CoderPatros.Jsf.dll [SHA_256]
[PASS]     CycloneDX.Core.dll [SHA_256]
[PASS]     JetBrains.Annotations.dll [SHA_256]
[PASS]     Json.More.dll [SHA_256]
[PASS]     JsonPointer.Net.dll [SHA_256]
[PASS]     JsonSchema.Net.dll [SHA_256]
[PASS]     protobuf-net.dll [SHA_256]
[PASS]     protobuf-net.Core.dll [SHA_256]
[PASS]     cs/System.CommandLine.resources.dll [SHA_256]
[PASS]     de/System.CommandLine.resources.dll [SHA_256]
[PASS]     es/System.CommandLine.resources.dll [SHA_256]
[PASS]     fr/System.CommandLine.resources.dll [SHA_256]
[PASS]     it/System.CommandLine.resources.dll [SHA_256]
[PASS]     ja/System.CommandLine.resources.dll [SHA_256]
[PASS]     ko/System.CommandLine.resources.dll [SHA_256]
[PASS]     pl/System.CommandLine.resources.dll [SHA_256]
[PASS]     pt-BR/System.CommandLine.resources.dll [SHA_256]
[PASS]     ru/System.CommandLine.resources.dll [SHA_256]
[PASS]     System.CommandLine.dll [SHA_256]
[PASS]     tr/System.CommandLine.resources.dll [SHA_256]
[PASS]     zh-Hans/System.CommandLine.resources.dll [SHA_256]
[PASS]     zh-Hant/System.CommandLine.resources.dll [SHA_256]
[PASS]     System.IO.Abstractions.dll [SHA_256]
[PASS]     TestableIO.System.IO.Abstractions.dll [SHA_256]
[PASS]     TestableIO.System.IO.Abstractions.Wrappers.dll [SHA_256]
[PASS]     Testably.Abstractions.FileSystem.Interface.dll [SHA_256]

=== Untracked File Detection ===
[IGNORED]   bom.json
[PASS] No untracked files found.

[PASS] All verifications passed.
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | All verifications passed |
| `1` | One or more verifications failed |
| `2` | Error (file not found, parse failure, path traversal detected, etc.) |

## Verification details

### Signature verification

If the SBOM contains a JSF (JSON Signature Format) signature, it is verified against either a provided JWK public key (`--key-file`) or an embedded key (`--allow-embedded-key`). If no signature is present, this check is skipped.

### Hash verification

All `file`-type components in the SBOM that have declared hashes are verified against the actual files on disk. Supported algorithms: MD5, SHA-1, SHA-256, SHA-384, SHA-512. Non-file components (libraries, applications, etc.) act as pass-through containers that propagate failures from nested file components.

Path traversal is prevented — component names that resolve outside the base directory are rejected.

### Untracked file detection

After hash verification, the tool scans the base directory for files that exist on disk but are not listed as file components in the SBOM. Any such file is reported as untracked and causes verification to fail.

Use `--ignore` with [Ant path patterns](https://ant.apache.org/manual/dirtasks.html#patterns) to exclude files from this check:

- `*.log` — exclude log files in the base directory
- `**/*.log` — exclude log files in any subdirectory
- `build/**` — exclude everything under the `build/` directory

## Installation

Pre-built binaries are available from the [GitHub Releases](https://github.com/coderpatros/cyclonedx-integrity-verification/releases) page. Download the archive for your platform:

| Platform | Archive |
|---|---|
| Linux (x64) | `cdx-verify-linux-x64.tar.gz` |
| Linux (ARM64) | `cdx-verify-linux-arm64.tar.gz` |
| macOS (Intel) | `cdx-verify-osx-x64.tar.gz` |
| macOS (Apple Silicon) | `cdx-verify-osx-arm64.tar.gz` |
| Windows (x64) | `cdx-verify-win-x64.zip` |
| Windows (ARM64) | `cdx-verify-win-arm64.zip` |

Extract the archive and place the `cdx-verify` binary (or `cdx-verify.exe` on Windows) somewhere on your `PATH`.

```bash
# Example for Linux (x64)
tar xzf cdx-verify-linux-x64.tar.gz
sudo mv cdx-verify /usr/local/bin/
```

## Building

Requires [.NET 8.0 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```bash
dotnet build
```

## Running tests

```bash
dotnet test
```

