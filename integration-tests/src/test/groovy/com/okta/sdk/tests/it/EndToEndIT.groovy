/*
 * Copyright 2020-Present Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License")
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
package com.okta.sdk.tests.it

import com.fasterxml.jackson.annotation.JsonInclude
import com.fasterxml.jackson.databind.DeserializationFeature
import com.fasterxml.jackson.databind.ObjectMapper
import com.fasterxml.jackson.databind.SerializationFeature
import com.github.tomakehurst.wiremock.WireMockServer
import com.github.tomakehurst.wiremock.client.WireMock
import com.github.tomakehurst.wiremock.http.HttpHeader
import com.github.tomakehurst.wiremock.matching.StringValuePattern
import com.google.common.collect.Sets
import com.okta.commons.http.MediaType
import com.okta.sdk.api.client.Clients
import com.okta.sdk.api.client.OktaIdentityEngineClient
import com.okta.sdk.api.model.Authenticator
import com.okta.sdk.api.model.Credentials
import com.okta.sdk.api.model.Options
import com.okta.sdk.api.model.RemediationOption
import com.okta.sdk.api.request.AnswerChallengeRequest
import com.okta.sdk.api.request.ChallengeRequest
import com.okta.sdk.api.request.IdentifyRequest
import com.okta.sdk.api.response.OktaIdentityEngineResponse
import org.testng.annotations.AfterClass
import org.testng.annotations.BeforeClass
import org.testng.annotations.Test
import wiremock.org.apache.http.HttpStatus

import javax.swing.JOptionPane

import static com.github.tomakehurst.wiremock.client.WireMock.*
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.aMapWithSize
import static org.hamcrest.Matchers.contains
import static org.hamcrest.Matchers.hasEntry
import static org.hamcrest.Matchers.hasSize
import static org.hamcrest.Matchers.notNullValue
import static org.hamcrest.Matchers.nullValue

class EndToEndIT {

    WireMockServer wireMockServer
    int mockPort

    ObjectMapper objectMapper
    OktaIdentityEngineClient oktaIdentityEngineClient

    @BeforeClass
    void setup() {
        mockPort = new ServerSocket(0).withCloseable {it.getLocalPort()}
        wireMockServer = new WireMockServer(options().bindAddress("127.0.0.1").port(mockPort))
        wireMockServer.start()

        objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)

        oktaIdentityEngineClient = Clients.builder()
            .setIssuer("http://localhost:" + mockPort)
            .setClientId("test-client-id")
            .setScopes(Sets.newHashSet("test-scope-1", "test-scope-2"))
            .build()
    }

    @Test
    void testEndToEnd() {

        // interact
        wireMockServer.stubFor(post(urlPathEqualTo("/oauth2/v1/interact"))
            //TODO: check for Authorization Header's presence
            .withHeader("Content-Type", containing(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .withBodyFile("interact-response.json")))

        OktaIdentityEngineResponse oktaIdentityEngineResponse = oktaIdentityEngineClient.interact()

        assertThat(oktaIdentityEngineResponse, notNullValue())

        wireMockServer.verify(postRequestedFor(urlEqualTo("/oauth2/v1/interact"))
            .withHeader("Content-Type", equalTo(MediaType.APPLICATION_FORM_URLENCODED_VALUE)))
        wireMockServer.resetAll()

        // introspect
        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/introspect"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("introspect-response.json")))

        oktaIdentityEngineResponse = oktaIdentityEngineClient.introspect("test-state-handle")

        assertThat(oktaIdentityEngineResponse, notNullValue())

        wireMockServer.verify(postRequestedFor(urlEqualTo("/idp/idx/introspect"))
            .withHeader("Content-Type", equalTo("application/ion+json;okta-version=1.0.0")))
        wireMockServer.resetAll()

        // identify
        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/identify"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("identify-response.json")))

        IdentifyRequest identifyRequest = new IdentifyRequest("test@example.com", "test-state-handle", false)
        oktaIdentityEngineResponse = oktaIdentityEngineClient.identify(identifyRequest)

        assertThat(oktaIdentityEngineResponse, notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation(), notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation().remediationOptions(), notNullValue())

        wireMockServer.verify(postRequestedFor(urlEqualTo("/idp/idx/identify"))
            .withHeader("Content-Type", equalTo("application/ion+json;okta-version=1.0.0")))
        wireMockServer.resetAll()

        // get remediation options to go to the next step

        RemediationOption[] remediationOptions = oktaIdentityEngineResponse.remediation().remediationOptions()
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
            .filter({ x -> ("select-authenticator-authenticate" == x.getName()) })
            .findFirst()
        RemediationOption remediationOption = remediationOptionsOptional.get()

        // get authenticator options
        Map<String, String> authenticatorOptionsMap = remediationOption.getAuthenticatorOptions()
        assertThat(authenticatorOptionsMap, aMapWithSize(3))
        assertThat(authenticatorOptionsMap, hasEntry("password", "aut2ihzk2n15tsQnQ1d6"))
        assertThat(authenticatorOptionsMap, hasEntry("security_question", "aut2ihzk4hgf9sIQa1d6"))
        assertThat(authenticatorOptionsMap, hasEntry("email", "aut2ihzk1gHl7ynhd1d6"))

        // select password authenticator challenge
        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/challenge"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("password-authenticator-challenge-response.json")))

        ChallengeRequest passwordAuthenticatorChallengeRequest =
            new ChallengeRequest("test-state-handle", new Authenticator(authenticatorOptionsMap.get("password"), "password"))
        oktaIdentityEngineResponse = remediationOptionsOptional.get().proceed(oktaIdentityEngineClient, passwordAuthenticatorChallengeRequest)

        assertThat(oktaIdentityEngineResponse, notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation(), notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation().remediationOptions(), notNullValue())

        wireMockServer.verify(postRequestedFor(urlEqualTo("/idp/idx/challenge"))
            .withHeader("Content-Type", equalTo("application/ion+json;okta-version=1.0.0")))
        wireMockServer.resetAll()

        // answer password authenticator challenge
        remediationOptions = oktaIdentityEngineResponse.remediation().remediationOptions()
        remediationOptionsOptional = Arrays.stream(remediationOptions)
            .filter({ x -> ("challenge-authenticator" == x.getName()) })
            .findFirst()

        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/challenge/answer"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("answer-password-authenticator-challenge-response.json")))

        AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest =
            new AnswerChallengeRequest("test-state-handle", new Credentials("some-password", null))
        oktaIdentityEngineResponse =
            remediationOptionsOptional.get().proceed(oktaIdentityEngineClient, passwordAuthenticatorAnswerChallengeRequest)

        assertThat(oktaIdentityEngineResponse, notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation(), notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation().remediationOptions(), notNullValue())

        wireMockServer.verify(postRequestedFor(urlEqualTo("/idp/idx/challenge/answer"))
            .withHeader("Content-Type", equalTo("application/ion+json;okta-version=1.0.0")))
        wireMockServer.resetAll()

        // get remediation options to go to the next step

        remediationOptions = oktaIdentityEngineResponse.remediation().remediationOptions()
        remediationOptionsOptional = Arrays.stream(remediationOptions)
            .filter({ x -> ("select-authenticator-authenticate" == x.getName()) })
            .findFirst()
        remediationOption = remediationOptionsOptional.get()

        authenticatorOptionsMap = remediationOption.getAuthenticatorOptions()
        assertThat(authenticatorOptionsMap, aMapWithSize(1))
        assertThat(authenticatorOptionsMap, hasEntry("email", "aut2ihzk1gHl7ynhd1d6"))

        // select email authenticator challenge (only one remaining)
        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/challenge"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("email-authenticator-challenge-response.json")))

        ChallengeRequest emailAuthenticatorChallengeRequest =
            new ChallengeRequest("test-state-handle", new Authenticator("sample@sample.com", "email"))
        oktaIdentityEngineResponse =
            remediationOptionsOptional.get().proceed(oktaIdentityEngineClient, emailAuthenticatorChallengeRequest)

        assertThat(oktaIdentityEngineResponse, notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation(), notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation().remediationOptions(), notNullValue())

        wireMockServer.verify(postRequestedFor(urlEqualTo("/idp/idx/challenge"))
            .withHeader("Content-Type", equalTo("application/ion+json;okta-version=1.0.0")))
        wireMockServer.resetAll()

        // answer email authenticator challenge
        remediationOptions = oktaIdentityEngineResponse.remediation().remediationOptions()
        remediationOptionsOptional = Arrays.stream(remediationOptions)
            .filter({ x -> ("challenge-authenticator" == x.getName()) })
            .findFirst()

        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/challenge/answer"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("answer-email-authenticator-challenge-response.json")))

        AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest =
            new AnswerChallengeRequest("test-state-handle", new Credentials("some-email-passcode", null))
        oktaIdentityEngineResponse =
            remediationOptionsOptional.get().proceed(oktaIdentityEngineClient, emailAuthenticatorAnswerChallengeRequest)

        assertThat(oktaIdentityEngineResponse, notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation(), nullValue()) // no more remediation steps

        wireMockServer.verify(postRequestedFor(urlEqualTo("/idp/idx/challenge/answer"))
            .withHeader("Content-Type", equalTo("application/ion+json;okta-version=1.0.0")))
        wireMockServer.resetAll()
    }

    @AfterClass
    void cleanUp() {
        wireMockServer.shutdown()
    }
}
