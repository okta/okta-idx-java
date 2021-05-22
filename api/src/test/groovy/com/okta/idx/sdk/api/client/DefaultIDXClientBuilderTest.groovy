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
package com.okta.idx.sdk.api.client

import com.okta.idx.sdk.api.io.DefaultResourceFactory
import com.okta.idx.sdk.api.io.Resource
import com.okta.idx.sdk.api.io.ResourceFactory
import com.okta.idx.sdk.api.util.Constants
import com.okta.idx.sdk.api.util.TestUtil
import com.okta.sdk.api.test.RestoreEnvironmentVariables
import com.okta.sdk.api.test.RestoreSystemProperties
import org.mockito.invocation.InvocationOnMock
import org.mockito.stubbing.Answer
import org.testng.annotations.Listeners
import org.testng.annotations.Test
import org.testng.collections.Sets

import static org.mockito.ArgumentMatchers.anyString
import static org.mockito.Mockito.*
import static org.testng.Assert.assertEquals
import static org.testng.Assert.assertTrue

@Listeners([RestoreSystemProperties, RestoreEnvironmentVariables])
class DefaultIDXClientBuilderTest {

    void clearOktaEnvAndSysProps() {
        System.clearProperty("okta.idx.issuer")
        System.clearProperty("okta.idx.clientId")
        System.clearProperty("okta.idx.clientSecret")
        System.clearProperty("okta.idx.scopes")
        System.clearProperty("okta.idx.redirectUri")

        RestoreEnvironmentVariables.setEnvironmentVariable("OKTA_IDX_ISSUER", null)
        RestoreEnvironmentVariables.setEnvironmentVariable("OKTA_IDX_CLIENTID", null)
        RestoreEnvironmentVariables.setEnvironmentVariable("OKTA_IDX_CLIENTSECRET", null)
        RestoreEnvironmentVariables.setEnvironmentVariable("OKTA_IDX_SCOPES", null)
        RestoreEnvironmentVariables.setEnvironmentVariable("OKTA_IDX_REDIRECTURI", null)
    }

    @Test
    void testBuilder() {
        assertTrue(Clients.builder() instanceof DefaultIDXClientBuilder)
    }

    @Test
    void testConfigureBaseProperties() {
        clearOktaEnvAndSysProps()
        DefaultIDXClientBuilder clientBuilder =
                new DefaultIDXClientBuilder(noDefaultYamlResourceFactory())
        assertEquals clientBuilder.clientConfig.issuer, "https://idx.okta.com"
        assertEquals clientBuilder.clientConfig.clientId, "idx-client-id"
        assertEquals clientBuilder.clientConfig.clientSecret, "idx-client-secret"
        assertEquals clientBuilder.clientConfig.scopes, ["idx-scope-1", "idx-scope-2"] as Set
        assertEquals clientBuilder.clientConfig.redirectUri, "https://okta.com"
    }

    @Test
    void testHttpBaseUrlForTesting() {
        clearOktaEnvAndSysProps()
        System.setProperty(Constants.DEFAULT_CLIENT_TESTING_DISABLE_HTTPS_CHECK_PROPERTY_NAME, "true")
        // shouldn't throw IllegalArgumentException
        new DefaultIDXClientBuilder(noDefaultYamlNoAppYamlResourceFactory())
                .setIssuer("http://okta.example.com")
                .setClientId("some-client-id")
                .setScopes(["test-scope"] as Set)
                .setRedirectUri("http://okta.com")
                .build()
    }

    @Test
    void testNullClientId() {
        clearOktaEnvAndSysProps()
        TestUtil.expect(IllegalArgumentException) {
            new DefaultIDXClientBuilder(noDefaultYamlNoAppYamlResourceFactory())
                    .setIssuer("https://okta.example.com")
                    .build()
        }
    }

    @Test
    void testMissingIssuer() {
        TestUtil.expect(IllegalArgumentException) {
            clearOktaEnvAndSysProps()
            new DefaultIDXClientBuilder(noDefaultYamlNoAppYamlResourceFactory())
                    .setClientId("test-client-id")
                    .setClientSecret("test-client-secret")
                    .setScopes([["test-scope-1", "test-scope-2"]] as Set<String>)
                    .setRedirectUri("https://redirect.com")
                    .build()
        }
    }

    @Test
    void testMissingScopes() {
        clearOktaEnvAndSysProps()
        TestUtil.expect(IllegalArgumentException) {
            new DefaultIDXClientBuilder(noDefaultYamlNoAppYamlResourceFactory())
                    .setIssuer("https://sample.com")
                    .setClientId("test-client-id")
                    .setClientSecret("test-client-secret")
                    .setRedirectUri("https://redirect.com")
                    .build()
        }
    }

    @Test
    void testEmptyIssuer() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultIDXClientBuilder()
                    .setIssuer(" ")
                    .setClientId("test-client-id")
                    .setClientSecret("test-client-secret")
                    .setScopes([["test-scope-1", "test-scope-2"]] as Set<String>)
                    .setRedirectUri("https://redirect.com")
                    .build()
        }
    }

    @Test
    void testEmptyClientId() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultIDXClientBuilder()
                    .setIssuer("https://sample.com")
                    .setClientId(" ")
                    .setClientSecret("test-client-secret")
                    .setScopes([["test-scope-1", "test-scope-2"]] as Set<String>)
                    .setRedirectUri("https://redirect.com")
                    .build()
        }
    }

    @Test
    void testEmptyScopes() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultIDXClientBuilder()
                    .setIssuer("https://sample.com")
                    .setClientId("test-client-id")
                    .setClientSecret("test-client-secret")
                    .setScopes(Sets.newHashSet())
                    .setRedirectUri("https://redirect.com")
                    .build()
        }
    }

    @Test
    void testEmptyRedirectUri() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultIDXClientBuilder()
                    .setIssuer("https://sample.com")
                    .setClientId("test-client-id")
                    .setClientSecret("test-client-secret")
                    .setScopes(Sets.newHashSet())
                    .build()
        }
    }

    static ResourceFactory noDefaultYamlNoAppYamlResourceFactory() {
        def resourceFactory = spy(new DefaultResourceFactory())
        doAnswer(new Answer<Resource>() {
            @Override
            Resource answer(InvocationOnMock invocation) throws Throwable {
                String arg = invocation.arguments[0].toString();
                if (arg.endsWith("/.okta/okta.yaml") || arg.equals("classpath:okta.yaml")) {
                    return mock(Resource)
                } else {
                    return invocation.callRealMethod()
                }
            }
        }).when(resourceFactory).createResource(anyString())

        return resourceFactory
    }

    static ResourceFactory noDefaultYamlResourceFactory() {
        def resourceFactory = spy(new DefaultResourceFactory())
        doAnswer(new Answer<Resource>() {
            @Override
            Resource answer(InvocationOnMock invocation) throws Throwable {
                if (invocation.arguments[0].toString().endsWith("/.okta/okta.yaml")) {
                    return mock(Resource)
                } else {
                    return invocation.callRealMethod()
                }
            }
        }).when(resourceFactory).createResource(anyString())

        return resourceFactory
    }
}
