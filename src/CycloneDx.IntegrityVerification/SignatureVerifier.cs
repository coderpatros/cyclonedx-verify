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

using System.Text.Json;
using System.Text.Json.Nodes;
using CoderPatros.Jsf;
using CoderPatros.Jsf.Keys;
using CoderPatros.Jsf.Models;

namespace CycloneDx.IntegrityVerification;

public record SignatureVerificationResult(
    bool Verified,
    bool SignaturePresent,
    string Message);

public static class SignatureVerifier
{
    public static SignatureVerificationResult Verify(
        string sbomJson,
        string? keyFilePath,
        bool allowEmbeddedKey)
    {
        var jsonObject = JsonNode.Parse(sbomJson)?.AsObject();
        if (jsonObject is null)
            return new SignatureVerificationResult(false, false, "Failed to parse SBOM JSON.");

        if (!jsonObject.ContainsKey("signature"))
            return new SignatureVerificationResult(true, false, "No signature found in SBOM. Skipping signature verification.");

        if (keyFilePath is null && !allowEmbeddedKey)
        {
            return new SignatureVerificationResult(false, true,
                "Signature found but no verification key provided. Use --key-file or --allow-embedded-key.");
        }

        var options = new VerificationOptions();

        if (keyFilePath is not null)
        {
            var jwkJson = File.ReadAllText(keyFilePath);
            var jwk = JsonSerializer.Deserialize<JwkPublicKey>(jwkJson);
            if (jwk is null)
                return new SignatureVerificationResult(false, true, $"Failed to deserialize JWK from {keyFilePath}.");

            var verificationKey = JwkKeyConverter.ToVerificationKey(jwk);
            options = options with { Key = verificationKey };
        }

        if (allowEmbeddedKey)
        {
            options = options with { AllowEmbeddedPublicKey = true };
        }

        var service = new JsfSignatureService();
        var result = service.Verify(jsonObject, options);

        if (result.IsValid)
            return new SignatureVerificationResult(true, true, "Signature verification passed.");
        else
            return new SignatureVerificationResult(false, true, $"Signature verification failed: {result.Error}");
    }
}
