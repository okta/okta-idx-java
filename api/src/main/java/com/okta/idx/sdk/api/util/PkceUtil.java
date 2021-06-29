/*
 * Copyright (c) 2020-Present, Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.okta.idx.sdk.api.util;

import com.okta.commons.lang.Assert;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class PkceUtil {

    public static final String CODE_CHALLENGE_METHOD = "S256";
    private static final int URL_SAFE_FLAG = 8;

    /**
     * Generate Code Challenge (Base64 URL-encoded SHA-256 hash of the generated code verifier).
     *
     * @param codeVerifier the code verifier
     * @return generated code challenge
     * @throws NoSuchAlgorithmException if no Provider supports a MessageDigestSpi
     *         implementation for the specified algorithm.
     */
    public static String generateCodeChallenge(String codeVerifier) throws NoSuchAlgorithmException {

        Assert.hasText(codeVerifier, "codeVerifier is required");
        byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
        MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
        messageDigest.update(bytes, 0, bytes.length);
        byte[] digest = messageDigest.digest();
        return base64Encode(digest);
    }

    /**
     * Generate Code Verifier (Random URL-safe string with a minimum length of 43 characters).
     *
     * @return generated code verifier
     */
    public static String generateCodeVerifier() {

        SecureRandom secureRandom = new SecureRandom();
        byte[] codeVerifier = new byte[32];
        secureRandom.nextBytes(codeVerifier);
        return base64Encode(codeVerifier);
    }

    private static String base64Encode(byte[] source) {
        try {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(source);
        } catch (NoClassDefFoundError e) {
            try {
                Method method = Class.forName("android.util.Base64").getMethod("encodeToString", byte[].class, int.class);
                String encoded = (String) method.invoke(null, source, URL_SAFE_FLAG);
                return encoded.substring(0, encoded.length() - 2); // Remove trailing "=\n".
            } catch (ClassNotFoundException | NoSuchMethodException | IllegalAccessException | InvocationTargetException exception) {
                throw new IllegalStateException("No Base64 Encoder found.", exception);
            }
        }
    }
}
