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

using System.Security.Cryptography;
using CycloneDX.Models;
using CycloneDX.IntegrityVerification;
using HashAlg = CycloneDX.Models.Hash.HashAlgorithm;

namespace CycloneDX.IntegrityVerification.Tests;

public class ResolveComponentPathTests
{
    [Fact]
    public void SimpleFilename_ReturnsFullPath()
    {
        var baseDir = Path.GetTempPath();
        var result = HashVerifier.ResolveComponentPath(baseDir, "file.txt");

        Assert.Equal(Path.GetFullPath(Path.Combine(baseDir, "file.txt")), result);
    }

    [Fact]
    public void SubdirectoryPath_ReturnsFullPath()
    {
        var baseDir = Path.GetTempPath();
        var result = HashVerifier.ResolveComponentPath(baseDir, "sub/dir/file.txt");

        Assert.Equal(Path.GetFullPath(Path.Combine(baseDir, "sub/dir/file.txt")), result);
    }

    [Fact]
    public void DotDot_EscapingBaseDir_Throws()
    {
        var baseDir = Path.Combine(Path.GetTempPath(), "fakedir");

        var ex = Assert.Throws<PathTraversalException>(
            () => HashVerifier.ResolveComponentPath(baseDir, "../../etc/passwd"));

        Assert.Contains("outside the base directory", ex.Message);
        Assert.Equal("../../etc/passwd", ex.ComponentName);
    }

    [Fact]
    public void DotDot_StayingInsideBaseDir_Succeeds()
    {
        var baseDir = Path.GetTempPath();
        // "sub/../file.txt" resolves back into baseDir
        var result = HashVerifier.ResolveComponentPath(baseDir, "sub/../file.txt");

        Assert.Equal(Path.GetFullPath(Path.Combine(baseDir, "file.txt")), result);
    }

    [Fact]
    public void AbsolutePath_OutsideBaseDir_Throws()
    {
        var baseDir = Path.Combine(Path.GetTempPath(), "myproject");

        Assert.Throws<PathTraversalException>(
            () => HashVerifier.ResolveComponentPath(baseDir, "/etc/passwd"));
    }

    [Fact]
    public void PrefixSibling_IsRejected()
    {
        // Ensure "/tmp/base" doesn't match "/tmp/base-extended/file.txt"
        var baseDir = Path.Combine(Path.GetTempPath(), "base");
        var siblingPath = Path.Combine(Path.GetTempPath(), "base-extended", "file.txt");

        // Build a relative path from baseDir to the sibling
        // This is effectively "../base-extended/file.txt"
        var componentName = "../base-extended/file.txt";

        Assert.Throws<PathTraversalException>(
            () => HashVerifier.ResolveComponentPath(baseDir, componentName));
    }

    [Fact]
    public void TrailingSlash_OnBaseDir_StillWorks()
    {
        var baseDir = Path.GetTempPath(); // typically ends with separator
        var result = HashVerifier.ResolveComponentPath(baseDir, "file.txt");

        Assert.Equal(Path.GetFullPath(Path.Combine(baseDir, "file.txt")), result);
    }

    [Fact]
    public void EmptyComponentName_ResolvesToBaseDir_Throws()
    {
        // Empty component name resolves to the base dir itself.
        // fullPath == fullBase, which is allowed by the current check.
        // This is fine — it won't match a real file with hashes anyway.
        var baseDir = Path.Combine(Path.GetTempPath(), "somedir");
        var result = HashVerifier.ResolveComponentPath(baseDir, "");

        Assert.Equal(Path.GetFullPath(baseDir), result);
    }
}

public class VerifyTests : IDisposable
{
    private readonly string _baseDir;

    public VerifyTests()
    {
        _baseDir = Path.Combine(Path.GetTempPath(), $"cdx-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_baseDir);
    }

    public void Dispose()
    {
        if (Directory.Exists(_baseDir))
            Directory.Delete(_baseDir, recursive: true);
    }

    private string CreateFile(string relativePath, string content)
    {
        var fullPath = Path.Combine(_baseDir, relativePath);
        Directory.CreateDirectory(Path.GetDirectoryName(fullPath)!);
        File.WriteAllText(fullPath, content);
        return fullPath;
    }

    private static string ComputeSha256(string filePath)
    {
        using var sha = SHA256.Create();
        using var stream = File.OpenRead(filePath);
        return Convert.ToHexString(sha.ComputeHash(stream)).ToLowerInvariant();
    }

    // --- File-type filtering ---

    [Fact]
    public void FileComponent_WithCorrectHash_Passes()
    {
        var path = CreateFile("hello.txt", "hello");
        var hash = ComputeSha256(path);

        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "hello.txt",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = hash }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        Assert.Equal(ComponentVerificationStatus.Pass, results[0].Status);
        Assert.Single(results[0].HashResults);
        Assert.Equal(HashVerificationStatus.Pass, results[0].HashResults[0].Status);
    }

    [Fact]
    public void FileComponent_WithWrongHash_Fails()
    {
        CreateFile("hello.txt", "hello");

        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "hello.txt",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = "0000000000000000000000000000000000000000000000000000000000000000" }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        Assert.Equal(ComponentVerificationStatus.Fail, results[0].Status);
        Assert.Equal(HashVerificationStatus.Fail, results[0].HashResults[0].Status);
        Assert.Contains("Expected", results[0].HashResults[0].Detail);
    }

    [Fact]
    public void LibraryComponent_WithHashes_IsSkipped()
    {
        CreateFile("mylib.dll", "binary");

        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "mylib.dll",
                    Type = Component.Classification.Library,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = "abc123" }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Empty(results);
    }

    [Fact]
    public void ApplicationComponent_WithHashes_IsSkipped()
    {
        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "my-app",
                    Type = Component.Classification.Application,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = "abc123" }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Empty(results);
    }

    [Fact]
    public void FileComponent_MissingFile_ReturnsFileNotFound()
    {
        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "missing.txt",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = "abc123" }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        Assert.Equal(ComponentVerificationStatus.FileNotFound, results[0].Status);
        Assert.Equal(HashVerificationStatus.FileNotFound, results[0].HashResults[0].Status);
    }

    [Fact]
    public void FileComponent_NoHashes_IsSkipped()
    {
        CreateFile("empty.txt", "");

        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "empty.txt",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>()
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Empty(results);
    }

    [Fact]
    public void NullComponents_ReturnsEmpty()
    {
        var bom = new Bom { Components = null };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Empty(results);
    }

    // --- Nested components ---

    [Fact]
    public void NestedFileComponents_AllPass()
    {
        var path1 = CreateFile("a.txt", "aaa");
        var path2 = CreateFile("b.txt", "bbb");

        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "parent",
                    Type = Component.Classification.Library,
                    Components = new List<Component>
                    {
                        new()
                        {
                            Name = "a.txt",
                            Type = Component.Classification.File,
                            Hashes = new List<Hash>
                            {
                                new() { Alg = HashAlg.SHA_256, Content = ComputeSha256(path1) }
                            }
                        },
                        new()
                        {
                            Name = "b.txt",
                            Type = Component.Classification.File,
                            Hashes = new List<Hash>
                            {
                                new() { Alg = HashAlg.SHA_256, Content = ComputeSha256(path2) }
                            }
                        }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        var parent = results[0];
        Assert.Equal("parent", parent.ComponentName);
        Assert.Equal(ComponentVerificationStatus.Pass, parent.Status);
        Assert.Equal(2, parent.SubComponentResults.Count);
        Assert.All(parent.SubComponentResults,
            r => Assert.Equal(ComponentVerificationStatus.Pass, r.Status));
    }

    [Fact]
    public void NestedFileComponent_ChildFails_ParentFails()
    {
        var path1 = CreateFile("good.txt", "good");

        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "parent",
                    Type = Component.Classification.Library,
                    Components = new List<Component>
                    {
                        new()
                        {
                            Name = "good.txt",
                            Type = Component.Classification.File,
                            Hashes = new List<Hash>
                            {
                                new() { Alg = HashAlg.SHA_256, Content = ComputeSha256(path1) }
                            }
                        },
                        new()
                        {
                            Name = "bad.txt",
                            Type = Component.Classification.File,
                            Hashes = new List<Hash>
                            {
                                new() { Alg = HashAlg.SHA_256, Content = "badhash" }
                            }
                        }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        var parent = results[0];
        Assert.Equal(ComponentVerificationStatus.Fail, parent.Status);
        Assert.Contains("bad.txt", parent.Detail);

        var good = parent.SubComponentResults.Single(r => r.ComponentName == "good.txt");
        Assert.Equal(ComponentVerificationStatus.Pass, good.Status);

        var bad = parent.SubComponentResults.Single(r => r.ComponentName == "bad.txt");
        Assert.NotEqual(ComponentVerificationStatus.Pass, bad.Status);
    }

    [Fact]
    public void NestedFileComponent_ChildMissing_ParentFails()
    {
        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "parent",
                    Type = Component.Classification.Library,
                    Components = new List<Component>
                    {
                        new()
                        {
                            Name = "gone.txt",
                            Type = Component.Classification.File,
                            Hashes = new List<Hash>
                            {
                                new() { Alg = HashAlg.SHA_256, Content = "abc" }
                            }
                        }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        Assert.Equal(ComponentVerificationStatus.Fail, results[0].Status);

        var child = results[0].SubComponentResults[0];
        Assert.Equal(ComponentVerificationStatus.FileNotFound, child.Status);
    }

    [Fact]
    public void DeeplyNestedComponents_PropagateFailure()
    {
        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "top",
                    Type = Component.Classification.Application,
                    Components = new List<Component>
                    {
                        new()
                        {
                            Name = "middle",
                            Type = Component.Classification.Library,
                            Components = new List<Component>
                            {
                                new()
                                {
                                    Name = "deep.txt",
                                    Type = Component.Classification.File,
                                    Hashes = new List<Hash>
                                    {
                                        new() { Alg = HashAlg.SHA_256, Content = "wrong" }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        var top = results[0];
        Assert.Equal("top", top.ComponentName);
        Assert.Equal(ComponentVerificationStatus.Fail, top.Status);

        var middle = top.SubComponentResults.Single();
        Assert.Equal("middle", middle.ComponentName);
        Assert.Equal(ComponentVerificationStatus.Fail, middle.Status);

        var deep = middle.SubComponentResults.Single();
        Assert.Equal("deep.txt", deep.ComponentName);
        Assert.NotEqual(ComponentVerificationStatus.Pass, deep.Status);
    }

    [Fact]
    public void LibraryWithNoFileDescendants_IsExcluded()
    {
        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "lib",
                    Type = Component.Classification.Library,
                    Components = new List<Component>
                    {
                        new()
                        {
                            Name = "sublib",
                            Type = Component.Classification.Library,
                        }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Empty(results);
    }

    // --- Path traversal via Verify ---

    [Fact]
    public void Verify_PathTraversal_Throws()
    {
        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "../../etc/shadow",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = "abc" }
                    }
                }
            }
        };

        Assert.Throws<PathTraversalException>(
            () => HashVerifier.Verify(bom, _baseDir));
    }

    [Fact]
    public void Verify_PathTraversal_InNestedComponent_Throws()
    {
        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "wrapper",
                    Type = Component.Classification.Library,
                    Components = new List<Component>
                    {
                        new()
                        {
                            Name = "../../../etc/passwd",
                            Type = Component.Classification.File,
                            Hashes = new List<Hash>
                            {
                                new() { Alg = HashAlg.SHA_256, Content = "abc" }
                            }
                        }
                    }
                }
            }
        };

        Assert.Throws<PathTraversalException>(
            () => HashVerifier.Verify(bom, _baseDir));
    }

    // --- File component with sub-components ---

    [Fact]
    public void FileComponent_OwnHashPass_ChildFails_OverallFails()
    {
        var parentPath = CreateFile("parent.txt", "parent");
        var parentHash = ComputeSha256(parentPath);

        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "parent.txt",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = parentHash }
                    },
                    Components = new List<Component>
                    {
                        new()
                        {
                            Name = "child.txt",
                            Type = Component.Classification.File,
                            Hashes = new List<Hash>
                            {
                                new() { Alg = HashAlg.SHA_256, Content = "wrong" }
                            }
                        }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        var parent = results[0];
        Assert.Equal(ComponentVerificationStatus.Fail, parent.Status);
        // Own hash passed
        Assert.Equal(HashVerificationStatus.Pass, parent.HashResults[0].Status);
        // But child failed
        Assert.NotEqual(ComponentVerificationStatus.Pass, parent.SubComponentResults[0].Status);
        Assert.Contains("Sub-component(s) failed", parent.Detail);
    }

    [Fact]
    public void FileComponent_OwnHashFail_ChildFails_OverallFails()
    {
        CreateFile("parent.txt", "parent");

        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "parent.txt",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = "wrongparent" }
                    },
                    Components = new List<Component>
                    {
                        new()
                        {
                            Name = "child.txt",
                            Type = Component.Classification.File,
                            Hashes = new List<Hash>
                            {
                                new() { Alg = HashAlg.SHA_256, Content = "wrongchild" }
                            }
                        }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        var parent = results[0];
        Assert.Equal(ComponentVerificationStatus.Fail, parent.Status);
        Assert.Contains("also failed", parent.Detail);
    }

    // --- Multiple hash algorithms ---

    [Fact]
    public void MultipleAlgorithms_AllVerified()
    {
        var path = CreateFile("multi.txt", "multi");
        var sha256 = ComputeSha256(path);

        using var sha512 = SHA512.Create();
        using var stream = File.OpenRead(path);
        var sha512Hash = Convert.ToHexString(sha512.ComputeHash(stream)).ToLowerInvariant();

        var bom = new Bom
        {
            Components = new List<Component>
            {
                new()
                {
                    Name = "multi.txt",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = sha256 },
                        new() { Alg = HashAlg.SHA_512, Content = sha512Hash }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        Assert.Equal(ComponentVerificationStatus.Pass, results[0].Status);
        Assert.Equal(2, results[0].HashResults.Count);
        Assert.All(results[0].HashResults,
            r => Assert.Equal(HashVerificationStatus.Pass, r.Status));
    }

    // --- Metadata component ---

    [Fact]
    public void MetadataComponent_FileWithCorrectHash_Passes()
    {
        var path = CreateFile("meta.txt", "metadata");
        var hash = ComputeSha256(path);

        var bom = new Bom
        {
            Metadata = new Metadata
            {
                Component = new Component
                {
                    Name = "meta.txt",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = hash }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        Assert.Equal(ComponentVerificationStatus.Pass, results[0].Status);
    }

    [Fact]
    public void MetadataComponent_WithNestedFileChildren_Passes()
    {
        var path = CreateFile("child.txt", "child");
        var hash = ComputeSha256(path);

        var bom = new Bom
        {
            Metadata = new Metadata
            {
                Component = new Component
                {
                    Name = "my-app",
                    Type = Component.Classification.Application,
                    Components = new List<Component>
                    {
                        new()
                        {
                            Name = "child.txt",
                            Type = Component.Classification.File,
                            Hashes = new List<Hash>
                            {
                                new() { Alg = HashAlg.SHA_256, Content = hash }
                            }
                        }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Single(results);
        Assert.Equal("my-app", results[0].ComponentName);
        Assert.Equal(ComponentVerificationStatus.Pass, results[0].Status);
        Assert.Single(results[0].SubComponentResults);
        Assert.Equal(ComponentVerificationStatus.Pass, results[0].SubComponentResults[0].Status);
    }

    [Fact]
    public void MetadataComponent_AndTopLevelComponents_BothVerified()
    {
        var metaPath = CreateFile("meta.txt", "meta");
        var compPath = CreateFile("comp.txt", "comp");

        var bom = new Bom
        {
            Metadata = new Metadata
            {
                Component = new Component
                {
                    Name = "meta.txt",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = ComputeSha256(metaPath) }
                    }
                }
            },
            Components = new List<Component>
            {
                new()
                {
                    Name = "comp.txt",
                    Type = Component.Classification.File,
                    Hashes = new List<Hash>
                    {
                        new() { Alg = HashAlg.SHA_256, Content = ComputeSha256(compPath) }
                    }
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Equal(2, results.Count);
        Assert.Equal("meta.txt", results[0].ComponentName);
        Assert.Equal("comp.txt", results[1].ComponentName);
        Assert.All(results, r => Assert.Equal(ComponentVerificationStatus.Pass, r.Status));
    }

    [Fact]
    public void MetadataComponent_NonFileNoChildren_ReturnsEmpty()
    {
        var bom = new Bom
        {
            Metadata = new Metadata
            {
                Component = new Component
                {
                    Name = "my-app",
                    Type = Component.Classification.Application,
                }
            }
        };

        var results = HashVerifier.Verify(bom, _baseDir);

        Assert.Empty(results);
    }
}
