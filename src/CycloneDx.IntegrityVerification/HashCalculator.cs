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
using HashAlg = CycloneDX.Models.Hash.HashAlgorithm;

namespace CycloneDx.IntegrityVerification;

public static class HashCalculator
{
    public static System.Security.Cryptography.HashAlgorithm? Create(HashAlg algorithm)
    {
        return algorithm switch
        {
            HashAlg.MD5 => MD5.Create(),
            HashAlg.SHA_1 => SHA1.Create(),
            HashAlg.SHA_256 => SHA256.Create(),
            HashAlg.SHA_384 => SHA384.Create(),
            HashAlg.SHA_512 => SHA512.Create(),
            _ => null,
        };
    }

    public static bool IsSupported(HashAlg algorithm)
    {
        return algorithm is HashAlg.MD5
            or HashAlg.SHA_1
            or HashAlg.SHA_256
            or HashAlg.SHA_384
            or HashAlg.SHA_512;
    }

    public static string ComputeHash(string filePath, HashAlg algorithm)
    {
        using var hashAlg = Create(algorithm)
            ?? throw new NotSupportedException($"Hash algorithm {algorithm} is not supported.");
        using var stream = File.OpenRead(filePath);
        var hashBytes = hashAlg.ComputeHash(stream);
        return Convert.ToHexString(hashBytes).ToLowerInvariant();
    }
}
