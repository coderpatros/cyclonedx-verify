// This file is part of CycloneDX Verify tool
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

using CycloneDX.Models;
using HashAlg = CycloneDX.Models.Hash.HashAlgorithm;

namespace CycloneDX.Verify;

public record ComponentVerificationResult(
    string ComponentName,
    ComponentVerificationStatus Status,
    List<HashResult> HashResults,
    List<ComponentVerificationResult> SubComponentResults,
    string? Detail = null);

public record HashResult(
    HashAlg Algorithm,
    HashVerificationStatus Status,
    string? Detail = null);

public enum ComponentVerificationStatus
{
    Pass,
    Fail,
    Skipped,
    FileNotFound,
}

public enum HashVerificationStatus
{
    Pass,
    Fail,
    Skipped,
    FileNotFound,
}

public class PathTraversalException : Exception
{
    public string ComponentName { get; }
    public string ResolvedPath { get; }

    public PathTraversalException(string componentName, string resolvedPath, string baseDir)
        : base($"Component \"{componentName}\" resolves to \"{resolvedPath}\" which is outside the base directory \"{baseDir}\"")
    {
        ComponentName = componentName;
        ResolvedPath = resolvedPath;
    }
}

public static class HashVerifier
{
    internal static string ResolveComponentPath(string baseDir, string componentName)
    {
        var fullBase = Path.GetFullPath(baseDir);
        var fullPath = Path.GetFullPath(Path.Combine(fullBase, componentName));

        // Ensure the resolved path is within the base directory
        var baseDirWithSeparator = fullBase.EndsWith(Path.DirectorySeparatorChar)
            ? fullBase
            : fullBase + Path.DirectorySeparatorChar;

        if (!fullPath.StartsWith(baseDirWithSeparator, StringComparison.Ordinal) && fullPath != fullBase)
            throw new PathTraversalException(componentName, fullPath, fullBase);

        return fullPath;
    }

    public static List<ComponentVerificationResult> Verify(Bom bom, string baseDir)
    {
        var results = new List<ComponentVerificationResult>();

        if (bom.Metadata?.Component is not null)
        {
            var result = VerifyComponent(bom.Metadata.Component, baseDir);
            if (result is not null)
                results.Add(result);
        }

        if (bom.Components is not null)
        {
            foreach (var component in bom.Components)
            {
                var result = VerifyComponent(component, baseDir);
                if (result is not null)
                    results.Add(result);
            }
        }

        return results;
    }

    private static ComponentVerificationResult? VerifyComponent(Component component, string baseDir)
    {
        // Process sub-components first (traverse all component types for nested children)
        var subResults = new List<ComponentVerificationResult>();
        if (component.Components is not null)
        {
            foreach (var sub in component.Components)
            {
                var subResult = VerifyComponent(sub, baseDir);
                if (subResult is not null)
                    subResults.Add(subResult);
            }
        }

        bool isFile = component.Type == Component.Classification.File;

        // Non-file components: only include if they have sub-component results to propagate
        if (!isFile)
        {
            if (subResults.Count == 0)
                return null;

            // Act as pass-through container: propagate failures from descendants
            bool anySubFailed = subResults.Any(r => r.Status != ComponentVerificationStatus.Pass);
            var status = anySubFailed ? ComponentVerificationStatus.Fail : ComponentVerificationStatus.Pass;
            var failedNames = subResults
                .Where(r => r.Status != ComponentVerificationStatus.Pass)
                .Select(r => r.ComponentName)
                .ToList();
            string? detail = anySubFailed
                ? $"Sub-component(s) failed: {string.Join(", ", failedNames)}"
                : null;

            return new ComponentVerificationResult(
                component.Name,
                status,
                new List<HashResult>(),
                subResults,
                detail);
        }

        // File component: verify hashes against the file on disk
        var hashResults = new List<HashResult>();

        if (component.Hashes is not null && component.Hashes.Count > 0)
        {
            var filePath = ResolveComponentPath(baseDir, component.Name);

            if (!File.Exists(filePath))
            {
                foreach (var hash in component.Hashes)
                {
                    hashResults.Add(new HashResult(
                        hash.Alg,
                        HashVerificationStatus.FileNotFound,
                        $"File not found: {filePath}"));
                }
            }
            else
            {
                foreach (var hash in component.Hashes)
                {
                    if (!HashCalculator.IsSupported(hash.Alg))
                    {
                        hashResults.Add(new HashResult(
                            hash.Alg,
                            HashVerificationStatus.Skipped,
                            $"Unsupported algorithm: {hash.Alg}"));
                        continue;
                    }

                    var computed = HashCalculator.ComputeHash(filePath, hash.Alg);
                    var expected = hash.Content;

                    if (string.Equals(computed, expected, StringComparison.OrdinalIgnoreCase))
                    {
                        hashResults.Add(new HashResult(hash.Alg, HashVerificationStatus.Pass));
                    }
                    else
                    {
                        hashResults.Add(new HashResult(
                            hash.Alg,
                            HashVerificationStatus.Fail,
                            $"Expected {expected}, got {computed}"));
                    }
                }
            }
        }

        // Determine overall status
        bool ownHashesFailed = hashResults.Any(r =>
            r.Status == HashVerificationStatus.Fail || r.Status == HashVerificationStatus.FileNotFound);
        bool anySubComponentFailed = subResults.Any(r => r.Status != ComponentVerificationStatus.Pass);

        ComponentVerificationStatus overallStatus;
        string? overallDetail = null;

        if (ownHashesFailed && anySubComponentFailed)
        {
            overallStatus = ComponentVerificationStatus.Fail;
            var failedSubs = subResults
                .Where(r => r.Status != ComponentVerificationStatus.Pass)
                .Select(r => r.ComponentName);
            overallDetail = $"Hash verification failed; sub-component(s) also failed: {string.Join(", ", failedSubs)}";
        }
        else if (ownHashesFailed)
        {
            // Check if it's specifically FileNotFound
            bool allFileNotFound = hashResults.All(r =>
                r.Status == HashVerificationStatus.FileNotFound || r.Status == HashVerificationStatus.Skipped);
            overallStatus = allFileNotFound ? ComponentVerificationStatus.FileNotFound : ComponentVerificationStatus.Fail;
        }
        else if (anySubComponentFailed)
        {
            overallStatus = ComponentVerificationStatus.Fail;
            var failedSubs = subResults
                .Where(r => r.Status != ComponentVerificationStatus.Pass)
                .Select(r => r.ComponentName);
            overallDetail = $"Sub-component(s) failed: {string.Join(", ", failedSubs)}";
        }
        else if (hashResults.Count == 0 && subResults.Count == 0)
        {
            // File component with no hashes and no sub-components — skip
            return null;
        }
        else
        {
            overallStatus = ComponentVerificationStatus.Pass;
        }

        return new ComponentVerificationResult(
            component.Name,
            overallStatus,
            hashResults,
            subResults,
            overallDetail);
    }
}
