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
package com.okta.sdk.impl.client

import com.okta.sdk.impl.util.TestUtil
import org.testng.annotations.Test

import com.okta.sdk.api.client.Clients
import org.testng.collections.Sets

import static org.testng.Assert.assertTrue

class DefaultOktaIdentityEngineClientBuilderTest {

    @Test
    void testBuilder() {
        assertTrue(Clients.builder() instanceof DefaultOktaIdentityEngineClientBuilder)
    }

    @Test
    void testMissingIssuer() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultOktaIdentityEngineClientBuilder()
                .setClientId("test-client-id")
                .setScopes([["test-scope-1", "test-scope-2"]] as Set<String>)
                .build()
        }
    }

    @Test
    void testMissingClientId() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultOktaIdentityEngineClientBuilder()
                .setIssuer("https://sample.com")
                .setScopes([["test-scope-1", "test-scope-2"]] as Set<String>)
                .build()
        }
    }

    @Test
    void testMissingScopes() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultOktaIdentityEngineClientBuilder()
                .setIssuer("https://sample.com")
                .setClientId("test-client-id")
                .build()
        }
    }

    @Test
    void testEmptyIssuer() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultOktaIdentityEngineClientBuilder()
                .setIssuer(" ")
                .setClientId("test-client-id")
                .setScopes([["test-scope-1", "test-scope-2"]] as Set<String>)
                .build()
        }
    }

    @Test
    void testEmptyClientId() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultOktaIdentityEngineClientBuilder()
                .setIssuer("https://sample.com")
                .setClientId(" ")
                .setScopes([["test-scope-1", "test-scope-2"]] as Set<String>)
                .build()
        }
    }

    @Test
    void testEmptyScopes() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultOktaIdentityEngineClientBuilder()
                .setIssuer("https://sample.com")
                .setClientId("test-client-id")
                .setScopes(Sets.newHashSet())
                .build()
        }
    }
}
