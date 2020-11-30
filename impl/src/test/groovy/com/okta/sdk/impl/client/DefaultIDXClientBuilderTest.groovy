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

import com.okta.sdk.api.client.Clients
import com.okta.sdk.api.client.IDXClientBuilder
import com.okta.sdk.impl.io.DefaultResourceFactory
import com.okta.sdk.impl.io.Resource
import com.okta.sdk.impl.io.ResourceFactory
import com.okta.sdk.impl.test.RestoreEnvironmentVariables
import com.okta.sdk.impl.test.RestoreSystemProperties
import com.okta.sdk.impl.util.TestUtil
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
        System.clearProperty("okta.client.clientId")
        System.clearProperty("okta.client.clientSecret")
        System.clearProperty("okta.client.scopes")

        RestoreEnvironmentVariables.setEnvironmentVariable("OKTA_IDX_ISSUER", null)
        RestoreEnvironmentVariables.setEnvironmentVariable("OKTA_CLIENT_CLIENTID", null)
        RestoreEnvironmentVariables.setEnvironmentVariable("OKTA_CLIENT_CLIENTSECRET", null)
        RestoreEnvironmentVariables.setEnvironmentVariable("OKTA_CLIENT_SCOPES", null)
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
        assertEquals clientBuilder.clientConfig.scopes, ["idx-scope-1", "idx-scope-2"] as Set
    }

    @Test
    void testHttpBaseUrlForTesting() {
        clearOktaEnvAndSysProps()
        System.setProperty(IDXClientBuilder.DEFAULT_CLIENT_TESTING_DISABLE_HTTPS_CHECK_PROPERTY_NAME, "true")
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
            new DefaultIDXClientBuilder(noDefaultYamlNoAppYamlResourceFactory())
                .setClientId("test-client-id")
                .setScopes([["test-scope-1", "test-scope-2"]] as Set<String>)
                .build()
        }
    }

    @Test
    void testMissingScopes() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultIDXClientBuilder(noDefaultYamlNoAppYamlResourceFactory())
                .setIssuer("https://sample.com")
                .setClientId("test-client-id")
                .build()
        }
    }

    @Test
    void testEmptyIssuer() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultIDXClientBuilder()
                .setIssuer(" ")
                .setClientId("test-client-id")
                .setScopes([["test-scope-1", "test-scope-2"]] as Set<String>)
                .build()
        }
    }

    @Test
    void testEmptyClientId() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultIDXClientBuilder()
                .setIssuer("https://sample.com")
                .setClientId(" ")
                .setScopes([["test-scope-1", "test-scope-2"]] as Set<String>)
                .build()
        }
    }

    @Test
    void testEmptyScopes() {
        TestUtil.expect(IllegalArgumentException) {
            new DefaultIDXClientBuilder()
                .setIssuer("https://sample.com")
                .setClientId("test-client-id")
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
