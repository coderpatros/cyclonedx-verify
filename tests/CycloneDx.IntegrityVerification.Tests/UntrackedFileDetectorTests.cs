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

using CycloneDx.IntegrityVerification;
using HashAlg = CycloneDX.Models.Hash.HashAlgorithm;

namespace CycloneDx.IntegrityVerification.Tests;

public class UntrackedFileDetectorTests : IDisposable
{
    private readonly string _baseDir;

    public UntrackedFileDetectorTests()
    {
        _baseDir = Path.Combine(Path.GetTempPath(), $"cdx-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_baseDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_baseDir))
            Directory.Delete(_baseDir, recursive: true);
    }

    private void CreateFile(string relativePath, string content = "")
    {
        var fullPath = Path.Combine(_baseDir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, content);
    }

    private static ComponentVerificationResult MakeFileResult(string name)
    {
        return new ComponentVerificationResult(
            name,
            ComponentVerificationStatus.Pass,
            new List<HashResult>
            {
                new(HashAlg.SHA_256, HashVerificationStatus.Pass)
            },
            new List<ComponentVerificationResult>());
    }

    [Fact]
    public void AllFilesTracked_ReturnsEmpty()
    {
        CreateFile("a.txt", "aaa");
        CreateFile("b.txt", "bbb");

        var results = new List<ComponentVerificationResult>
        {
            MakeFileResult("a.txt"),
            MakeFileResult("b.txt"),
        };

        var result = UntrackedFileDetector.DetectUntrackedFiles(
            _baseDir, results, Array.Empty<string>());

        Assert.Empty(result.UntrackedFiles);
        Assert.Empty(result.IgnoredFiles);
    }

    [Fact]
    public void UntrackedFileDetected_ReturnedInList()
    {
        CreateFile("a.txt", "aaa");
        CreateFile("extra.txt", "extra");

        var results = new List<ComponentVerificationResult>
        {
            MakeFileResult("a.txt"),
        };

        var result = UntrackedFileDetector.DetectUntrackedFiles(
            _baseDir, results, Array.Empty<string>());

        Assert.Single(result.UntrackedFiles);
        Assert.Equal("extra.txt", result.UntrackedFiles[0]);
        Assert.Empty(result.IgnoredFiles);
    }

    [Fact]
    public void IgnorePattern_ExcludesFile()
    {
        CreateFile("a.txt", "aaa");
        CreateFile("extra.log", "log");

        var results = new List<ComponentVerificationResult>
        {
            MakeFileResult("a.txt"),
        };

        var result = UntrackedFileDetector.DetectUntrackedFiles(
            _baseDir, results, new[] { "*.log" });

        Assert.Empty(result.UntrackedFiles);
        Assert.Single(result.IgnoredFiles);
        Assert.Equal("extra.log", result.IgnoredFiles[0]);
    }

    [Fact]
    public void IgnorePatternWithDoubleStarGlob_ExcludesNestedFiles()
    {
        CreateFile("a.txt", "aaa");
        CreateFile("logs/debug.log", "log1");
        CreateFile("logs/sub/trace.log", "log2");

        var results = new List<ComponentVerificationResult>
        {
            MakeFileResult("a.txt"),
        };

        var result = UntrackedFileDetector.DetectUntrackedFiles(
            _baseDir, results, new[] { "**/*.log" });

        Assert.Empty(result.UntrackedFiles);
        Assert.Equal(2, result.IgnoredFiles.Count);
        Assert.Contains("logs/debug.log", result.IgnoredFiles);
        Assert.Contains("logs/sub/trace.log", result.IgnoredFiles);
    }

    [Fact]
    public void SubdirectoryFileUntracked_Detected()
    {
        CreateFile("a.txt", "aaa");
        CreateFile("sub/untracked.txt", "extra");

        var results = new List<ComponentVerificationResult>
        {
            MakeFileResult("a.txt"),
        };

        var result = UntrackedFileDetector.DetectUntrackedFiles(
            _baseDir, results, Array.Empty<string>());

        Assert.Single(result.UntrackedFiles);
        Assert.Equal("sub/untracked.txt", result.UntrackedFiles[0]);
    }

    [Fact]
    public void IgnoreEntireDirectory_ExcludesAllContents()
    {
        CreateFile("a.txt", "aaa");
        CreateFile("build/output.bin", "bin");
        CreateFile("build/sub/other.bin", "bin2");

        var results = new List<ComponentVerificationResult>
        {
            MakeFileResult("a.txt"),
        };

        var result = UntrackedFileDetector.DetectUntrackedFiles(
            _baseDir, results, new[] { "build/**" });

        Assert.Empty(result.UntrackedFiles);
        Assert.Equal(2, result.IgnoredFiles.Count);
        Assert.Contains("build/output.bin", result.IgnoredFiles);
        Assert.Contains("build/sub/other.bin", result.IgnoredFiles);
    }

    [Fact]
    public void EmptyResults_NoFileComponents_AllFilesUntracked()
    {
        CreateFile("a.txt", "aaa");
        CreateFile("b.txt", "bbb");

        var results = new List<ComponentVerificationResult>();

        var result = UntrackedFileDetector.DetectUntrackedFiles(
            _baseDir, results, Array.Empty<string>());

        Assert.Equal(2, result.UntrackedFiles.Count);
        Assert.Contains("a.txt", result.UntrackedFiles);
        Assert.Contains("b.txt", result.UntrackedFiles);
    }

    [Fact]
    public void NestedComponentResults_VerifiedPathsExtracted()
    {
        CreateFile("a.txt", "aaa");
        CreateFile("sub/b.txt", "bbb");
        CreateFile("extra.txt", "extra");

        var nestedResult = new ComponentVerificationResult(
            "parent",
            ComponentVerificationStatus.Pass,
            new List<HashResult>(),
            new List<ComponentVerificationResult>
            {
                MakeFileResult("a.txt"),
                MakeFileResult("sub/b.txt"),
            });

        var results = new List<ComponentVerificationResult> { nestedResult };

        var result = UntrackedFileDetector.DetectUntrackedFiles(
            _baseDir, results, Array.Empty<string>());

        Assert.Single(result.UntrackedFiles);
        Assert.Equal("extra.txt", result.UntrackedFiles[0]);
    }
}
