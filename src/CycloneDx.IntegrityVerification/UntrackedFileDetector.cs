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

using AntPathMatching;

namespace CycloneDx.IntegrityVerification;

public record UntrackedFileResult(List<string> UntrackedFiles, List<string> IgnoredFiles);

public static class UntrackedFileDetector
{
    public static UntrackedFileResult DetectUntrackedFiles(
        string baseDir,
        List<ComponentVerificationResult> verificationResults,
        IEnumerable<string> ignorePatterns)
    {
        // Collect verified paths from the verification result tree
        var verifiedPaths = new HashSet<string>(StringComparer.Ordinal);
        foreach (var result in verificationResults)
        {
            CollectVerifiedPaths(result, verifiedPaths);
        }

        // Enumerate all files on disk, convert to forward-slash relative paths
        var fullBase = Path.GetFullPath(baseDir);
        var diskFiles = Directory.EnumerateFiles(fullBase, "*", SearchOption.AllDirectories)
            .Select(f => Path.GetRelativePath(fullBase, f).Replace('\\', '/'))
            .ToList();

        // Apply ignore patterns
        var antPatterns = ignorePatterns
            .Where(p => !string.IsNullOrWhiteSpace(p))
            .Select(p => new Ant(p))
            .ToList();

        var nonVerified = diskFiles
            .Where(f => !verifiedPaths.Contains(f))
            .ToList();

        var ignored = nonVerified
            .Where(f => antPatterns.Any(a => a.IsMatch(f)))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        var untracked = nonVerified
            .Where(f => !antPatterns.Any(a => a.IsMatch(f)))
            .OrderBy(f => f, StringComparer.Ordinal)
            .ToList();

        return new UntrackedFileResult(untracked, ignored);
    }

    private static void CollectVerifiedPaths(
        ComponentVerificationResult result,
        HashSet<string> paths)
    {
        if (result.HashResults.Count > 0)
        {
            paths.Add(result.ComponentName.Replace('\\', '/'));
        }

        foreach (var sub in result.SubComponentResults)
        {
            CollectVerifiedPaths(sub, paths);
        }
    }
}
