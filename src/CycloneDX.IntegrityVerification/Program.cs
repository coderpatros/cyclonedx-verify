// This file is part of CycloneDX Integrity Verification tool
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0
// Copyright (c) Patrick Dwyer. All Rights Reserved.

using System.CommandLine;
using CycloneDX.Json;
using CycloneDX.IntegrityVerification;

var sbomFileArg = new Argument<FileInfo>(
    "sbom-file",
    "Path to the CycloneDX SBOM JSON file");

var baseDirOption = new Option<DirectoryInfo?>(
    "--base-dir",
    "Base directory for resolving component file paths (default: current directory)");

var keyFileOption = new Option<FileInfo?>(
    "--key-file",
    "Path to a JWK public key file for signature verification");

var allowEmbeddedKeyOption = new Option<bool>(
    "--allow-embedded-key",
    "Allow embedded public keys in JSF signatures");

var ignoreOption = new Option<string[]>(
    "--ignore",
    "Ant path patterns for files/directories to exclude from untracked file detection")
{ AllowMultipleArgumentsPerToken = true };

var rootCommand = new RootCommand("Verify the integrity of a CycloneDX SBOM")
{
    sbomFileArg,
    baseDirOption,
    keyFileOption,
    allowEmbeddedKeyOption,
    ignoreOption,
};

rootCommand.SetHandler(
    (FileInfo sbomFile, DirectoryInfo? baseDir, FileInfo? keyFile, bool allowEmbeddedKey, string[] ignore) =>
    {
        return Task.FromResult(Run(sbomFile, baseDir, keyFile, allowEmbeddedKey, ignore));
    },
    sbomFileArg, baseDirOption, keyFileOption, allowEmbeddedKeyOption, ignoreOption);

return await rootCommand.InvokeAsync(args);

static int Run(FileInfo sbomFile, DirectoryInfo? baseDir, FileInfo? keyFile, bool allowEmbeddedKey, string[] ignorePatterns)
{
    if (!sbomFile.Exists)
    {
        WriteError($"SBOM file not found: {sbomFile.FullName}");
        return 2;
    }

    var baseDirPath = baseDir?.FullName ?? Directory.GetCurrentDirectory();

    string sbomJson;
    try
    {
        sbomJson = File.ReadAllText(sbomFile.FullName);
    }
    catch (Exception ex)
    {
        WriteError($"Failed to read SBOM file: {ex.Message}");
        return 2;
    }

    // Signature verification
    bool overallPass = true;

    Console.WriteLine("=== Signature Verification ===");
    try
    {
        var sigResult = SignatureVerifier.Verify(
            sbomJson,
            keyFile?.FullName,
            allowEmbeddedKey);

        if (!sigResult.SignaturePresent)
        {
            WriteSkipped(sigResult.Message);
        }
        else if (sigResult.Verified)
        {
            WritePass(sigResult.Message);
        }
        else
        {
            WriteFail(sigResult.Message);
            overallPass = false;
        }
    }
    catch (Exception ex)
    {
        WriteError($"Signature verification error: {ex.Message}");
        return 2;
    }

    Console.WriteLine();

    // Hash verification
    Console.WriteLine("=== Hash Verification ===");

    CycloneDX.Models.Bom bom;
    try
    {
        bom = Serializer.Deserialize(sbomJson);
    }
    catch (Exception ex)
    {
        Console.WriteLine(sbomJson);
        WriteError($"Failed to parse SBOM: {ex.Message}");
        return 2;
    }

    List<ComponentVerificationResult> hashResults;
    try
    {
        hashResults = HashVerifier.Verify(bom, baseDirPath);
    }
    catch (PathTraversalException ex)
    {
        WriteError($"Path traversal detected: {ex.Message}");
        return 2;
    }

    if (hashResults.Count == 0)
    {
        WriteSkipped("No components with hashes found.");
    }
    else
    {
        foreach (var result in hashResults)
        {
            PrintComponentResult(result, indent: 1);
            if (result.Status != ComponentVerificationStatus.Pass)
                overallPass = false;
        }
    }

    // Untracked file detection
    Console.WriteLine();
    Console.WriteLine("=== Untracked File Detection ===");

    var untrackedResult = UntrackedFileDetector.DetectUntrackedFiles(
        baseDirPath, hashResults, ignorePatterns ?? Array.Empty<string>());

    foreach (var file in untrackedResult.IgnoredFiles)
    {
        WriteIgnored($"  {file}");
    }

    if (untrackedResult.UntrackedFiles.Count == 0)
    {
        WritePass("No untracked files found.");
    }
    else
    {
        foreach (var file in untrackedResult.UntrackedFiles)
        {
            WriteFail($"  {file}");
        }
        WriteFail($"{untrackedResult.UntrackedFiles.Count} untracked file(s) found in base directory.");
        overallPass = false;
    }

    Console.WriteLine();
    if (overallPass)
    {
        WritePass("All verifications passed.");
        return 0;
    }
    else
    {
        WriteFail("One or more verifications failed.");
        return 1;
    }
}

static void PrintComponentResult(ComponentVerificationResult result, int indent)
{
    var prefix = new string(' ', indent * 2);

    // Print hash results for this component
    foreach (var hr in result.HashResults)
    {
        var label = $"{prefix}{result.ComponentName} [{hr.Algorithm}]";
        switch (hr.Status)
        {
            case HashVerificationStatus.Pass:
                WritePass(label);
                break;
            case HashVerificationStatus.Fail:
                WriteFail($"{label}: {hr.Detail}");
                break;
            case HashVerificationStatus.Skipped:
                WriteSkipped($"{label}: {hr.Detail}");
                break;
            case HashVerificationStatus.FileNotFound:
                WriteFail($"{label}: {hr.Detail}");
                break;
        }
    }

    // Print sub-component results
    foreach (var sub in result.SubComponentResults)
    {
        PrintComponentResult(sub, indent + 1);
    }

    // Print propagation detail if this component failed due to sub-components
    if (result.Detail is not null && result.SubComponentResults.Count > 0)
    {
        if (result.Status == ComponentVerificationStatus.Fail)
            WriteFail($"{prefix}{result.Detail}");
        else
            WritePass($"{prefix}{result.Detail}");
    }
}

static void WritePass(string message)
{
    WriteColored("[PASS] ", ConsoleColor.Green);
    Console.WriteLine(message);
}

static void WriteFail(string message)
{
    WriteColored("[FAIL] ", ConsoleColor.Red);
    Console.WriteLine(message);
}

static void WriteSkipped(string message)
{
    WriteColored("[SKIP] ", ConsoleColor.Yellow);
    Console.WriteLine(message);
}

static void WriteIgnored(string message)
{
    WriteColored("[IGNORED] ", ConsoleColor.DarkGray);
    Console.WriteLine(message);
}

static void WriteError(string message)
{
    WriteColored("[ERROR] ", ConsoleColor.Red);
    Console.Error.WriteLine(message);
}

static void WriteColored(string prefix, ConsoleColor color)
{
    if (!Console.IsOutputRedirected)
        Console.ForegroundColor = color;
    Console.Write(prefix);
    if (!Console.IsOutputRedirected)
        Console.ResetColor();
}
