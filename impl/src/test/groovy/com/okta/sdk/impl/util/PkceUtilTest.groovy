/*
 * Copyright 2020-Present Okta, Inc.
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
package com.okta.sdk.impl.util

import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.notNullValue
import static org.hamcrest.Matchers.is

class PkceUtilTest {

    @Test
    void testGenerateCodeVerifier() {
        String codeVerifier = PkceUtil.generateCodeVerifier()
        assertThat codeVerifier, notNullValue()
    }

    @Test
    void testGenerateCodeChallenge_NullCodeVerifier() {
        def exception = TestUtil.expect IllegalArgumentException, { PkceUtil.generateCodeChallenge(null) }
        assertThat exception.getMessage(), is("codeVerifier is required")
    }

    @Test
    void testGenerateCodeChallenge() {
        String codeVerifier = PkceUtil.generateCodeVerifier()
        String codeChallenge = PkceUtil.generateCodeChallenge(codeVerifier)
        assertThat codeChallenge, notNullValue()
    }
}