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
package com.okta.sdk.tests.it.util

import com.google.common.collect.Sets
import com.okta.commons.lang.Strings
import com.okta.sdk.api.client.Clients
import com.okta.sdk.api.client.OktaIdentityEngineClient
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import org.testng.IHookCallBack
import org.testng.IHookable
import org.testng.ITestResult
import org.testng.annotations.AfterMethod
import org.testng.annotations.Listeners
/**
 * Creates a thread local client for a test method to use. The client may be connected to an actual Okta instance or a Test Server.
 */
@Listeners(ClientProvider)
trait ClientProvider implements IHookable {

    private Logger log = LoggerFactory.getLogger(ClientProvider)

    private ThreadLocal<OktaIdentityEngineClient> threadLocal = new ThreadLocal<>()
    private ThreadLocal<String> testName = new ThreadLocal<>()

    OktaIdentityEngineClient getClient(String scenarioId = null) {
        OktaIdentityEngineClient client = threadLocal.get()
        if (client == null) {
            threadLocal.set(buildClient(scenarioId))
        }
        return threadLocal.get()
    }

    private isRunningWithTestServer() {
        return Strings.hasText(System.getProperty(TestServer.TEST_SERVER_BASE_URL))
    }

    private OktaIdentityEngineClient buildClient(String scenarioId = null) {

        String testServerBaseUrl = System.getProperty(TestServer.TEST_SERVER_BASE_URL)
        if (isRunningWithTestServer() && scenarioId != null) {
            return Clients.builder()
                .setIssuer(testServerBaseUrl + scenarioId)
                .setClientId("test-client-id")
                .setScopes(["test-scope-1", "test-scope-2"] as Set<String>)
                .build()
        }

        OktaIdentityEngineClient client = Clients.builder()
            .setIssuer("https://devex-idx-testing.oktapreview.com") //TODO: remove hardcoding
            .setClientId("test-client-id")
            .setScopes(Sets.newHashSet("test-scope-1", "test-scope-2"))
            .build()

        return client
    }

    @Override
    void run(IHookCallBack callBack, ITestResult testResult) {

        testName.set(testResult.name)

        try {
            // run the tests
            callBack.runTestMethod(testResult)
        }
        finally {
            // cleanup the thread local
            threadLocal.remove()
            testName.remove()
        }
    }

    def getTestName() {
        return "okta-identity-engine-java-sdk-" + testName.get()
    }

    def getUniqueTestName() {
        return "${getTestName()}-${UUID.randomUUID()}"
    }

    @AfterMethod
    void clean() {
        if (!isRunningWithTestServer()) {
            //TODO
        }
    }
}
