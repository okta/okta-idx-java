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
import com.okta.commons.http.MediaType
import com.okta.sdk.api.client.Clients
import com.okta.sdk.api.client.OktaIdentityEngineClient
import com.okta.sdk.api.model.Authenticator
import com.okta.sdk.api.model.Credentials
import com.okta.sdk.api.model.RemediationOption
import com.okta.sdk.api.request.AnswerChallengeRequest
import com.okta.sdk.api.request.AnswerChallengeRequestBuilder
import com.okta.sdk.api.request.ChallengeRequest
import com.okta.sdk.api.request.ChallengeRequestBuilder
import com.okta.sdk.api.request.IdentifyRequest
import com.okta.sdk.api.request.IdentifyRequestBuilder
import com.okta.sdk.api.response.InteractResponse
import com.okta.sdk.api.response.OktaIdentityEngineResponse
import org.testng.annotations.AfterClass
import org.testng.annotations.BeforeClass
import org.testng.annotations.Test
import wiremock.org.apache.http.HttpStatus

import static com.github.tomakehurst.wiremock.client.WireMock.*
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options
import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*

class EndToEndIT {

    WireMockServer wireMockServer
    int mockPort

    ObjectMapper objectMapper
    OktaIdentityEngineClient oktaIdentityEngineClient

    @BeforeClass
    void setup() {
        mockPort = new ServerSocket(0).withCloseable {it.getLocalPort()}
        wireMockServer = new WireMockServer(options().bindAddress("localhost").port(mockPort))
        wireMockServer.start()

        objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL)

        oktaIdentityEngineClient = Clients.builder()
            .setIssuer("http://localhost:" + mockPort)
            .setClientId("test-client-id")
            .setClientSecret("test-client-secret")
            .setScopes(["test-scope-1", "test-scope-2"] as Set)
            .build()
    }

    @Test
    void testWithPasswordAndEmailAuthenticators() {

        // interact
        wireMockServer.stubFor(post(urlPathEqualTo("/oauth2/v1/interact"))
            //TODO: check for Authorization Header's presence?
            .withHeader("Content-Type", containing(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .withBodyFile("interact-response.json")))

        InteractResponse interactResponse = oktaIdentityEngineClient.interact()

        assertThat(interactResponse, notNullValue())
        assertThat(interactResponse.getInteractionHandle(), is("003Q14X7li"))

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

        OktaIdentityEngineResponse oktaIdentityEngineResponse = oktaIdentityEngineClient.introspect("introspectionHandle")

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

        IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
            .withIdentifier("test@example.com")
            .withRememberMe(false)
            .withStateHandle("stateHandle")
            .build()
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

        Authenticator passwordAuthenticator = new Authenticator()
        passwordAuthenticator.setId(authenticatorOptionsMap.get("password"))
        passwordAuthenticator.setMethodType("password")

        ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
            .withStateHandle("stateHandle")
            .withAuthenticator(passwordAuthenticator)
            .build()
        oktaIdentityEngineResponse = remediationOption.proceed(oktaIdentityEngineClient, passwordAuthenticatorChallengeRequest)

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
        remediationOption = remediationOptionsOptional.get()

        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/challenge/answer"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("answer-password-authenticator-challenge-response.json")))

        Credentials passwordCredentials = new Credentials()
        passwordCredentials.setPasscode("some=password")

        AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
            .withStateHandle("stateHandle")
            .withCredentials(passwordCredentials)
            .build()
        oktaIdentityEngineResponse = remediationOption.proceed(oktaIdentityEngineClient, passwordAuthenticatorAnswerChallengeRequest)

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

        Authenticator emailAuthenticator = new Authenticator()
        emailAuthenticator.setId(authenticatorOptionsMap.get("email"))
        emailAuthenticator.setMethodType("email")

        ChallengeRequest emailAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
            .withStateHandle("stateHandle")
            .withAuthenticator(emailAuthenticator)
            .build()
        oktaIdentityEngineResponse = remediationOption.proceed(oktaIdentityEngineClient, emailAuthenticatorChallengeRequest)

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
        remediationOption = remediationOptionsOptional.get()

        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/challenge/answer"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("answer-email-authenticator-challenge-response.json")))

        Credentials emailPasscodeCredentials = new Credentials()
        emailPasscodeCredentials.setPasscode("some-email-passcode")

        AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
            .withStateHandle("stateHandle")
            .withCredentials(emailPasscodeCredentials)
            .build()
        oktaIdentityEngineResponse = remediationOption.proceed(oktaIdentityEngineClient, emailAuthenticatorAnswerChallengeRequest)

        assertThat(oktaIdentityEngineResponse, notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation(), nullValue()) // no more remediation steps

        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode(), notNullValue())
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().getRel(), notNullValue())
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().getName(), notNullValue())
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().getHref(), notNullValue())
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().getMethod(), is("POST"))
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().getValue(), notNullValue())
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().parseGrantType(), is("interaction_code"))
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().parseInteractionCode(), is("Txd_5odx08kzZ_oxeEbBk8PNjI5UDnTM2P1rMCmHDyA"))
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().parseClientId(), is("0oa3jxy2kpqZs9fOU0g7"))

        wireMockServer.verify(postRequestedFor(urlEqualTo("/idp/idx/challenge/answer"))
            .withHeader("Content-Type", equalTo("application/ion+json;okta-version=1.0.0")))
        wireMockServer.resetAll()
    }

    @Test
    void testWithSecurityQnAndEmailAuthenticators() {

        // interact
        wireMockServer.stubFor(post(urlPathEqualTo("/oauth2/v1/interact"))
        //TODO: check for Authorization Header's presence?
            .withHeader("Content-Type", containing(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", MediaType.APPLICATION_JSON_VALUE)
                .withBodyFile("interact-response.json")))

        InteractResponse interactResponse = oktaIdentityEngineClient.interact()

        assertThat(interactResponse, notNullValue())
        assertThat(interactResponse.getInteractionHandle(), is("003Q14X7li"))

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

        OktaIdentityEngineResponse oktaIdentityEngineResponse = oktaIdentityEngineClient.introspect("introspectionHandle")

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

        IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
            .withIdentifier("test@example.com")
            .withRememberMe(false)
            .withStateHandle("stateHandle")
            .build()
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

        // select security question authenticator challenge
        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/challenge"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("security-qn-authenticator-challenge-response.json")))

        Authenticator secQnAuthenticator = new Authenticator()
        secQnAuthenticator.setId(authenticatorOptionsMap.get("security_question"))
        secQnAuthenticator.setMethodType("security_question")

        ChallengeRequest secQnAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
            .withStateHandle("stateHandle")
            .withAuthenticator(secQnAuthenticator)
            .build()
        oktaIdentityEngineResponse = remediationOption.proceed(oktaIdentityEngineClient, secQnAuthenticatorChallengeRequest)

        assertThat(oktaIdentityEngineResponse, notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation(), notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation().remediationOptions(), notNullValue())

        wireMockServer.verify(postRequestedFor(urlEqualTo("/idp/idx/challenge"))
            .withHeader("Content-Type", equalTo("application/ion+json;okta-version=1.0.0")))
        wireMockServer.resetAll()

        // answer security question authenticator challenge
        remediationOptions = oktaIdentityEngineResponse.remediation().remediationOptions()
        remediationOptionsOptional = Arrays.stream(remediationOptions)
            .filter({ x -> ("challenge-authenticator" == x.getName()) })
            .findFirst()
        remediationOption = remediationOptionsOptional.get()

        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/challenge/answer"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("answer-security-qn-authenticator-challenge-response.json")))

        Credentials secQnAnswerCredentials = new Credentials()
        secQnAnswerCredentials.setAnswer("answer to security question")

        AnswerChallengeRequest secQnAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
            .withStateHandle("stateHandle")
            .withCredentials(secQnAnswerCredentials)
            .build()
        oktaIdentityEngineResponse = remediationOption.proceed(oktaIdentityEngineClient, secQnAuthenticatorAnswerChallengeRequest)

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

        Authenticator emailAuthenticator = new Authenticator()
        emailAuthenticator.setId(authenticatorOptionsMap.get("email"))
        emailAuthenticator.setMethodType("email")

        ChallengeRequest emailAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
            .withStateHandle("stateHandle")
            .withAuthenticator(emailAuthenticator)
            .build()
        oktaIdentityEngineResponse = remediationOption.proceed(oktaIdentityEngineClient, emailAuthenticatorChallengeRequest)

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
        remediationOption = remediationOptionsOptional.get()

        wireMockServer.stubFor(post(urlPathEqualTo("/idp/idx/challenge/answer"))
            .withHeader("Content-Type", containing("application/ion+json;okta-version=1.0.0"))
            .willReturn(aResponse()
                .withStatus(HttpStatus.SC_OK)
                .withHeader("Content-Type", "application/ion+json;okta-version=1.0.0")
                .withBodyFile("answer-email-authenticator-challenge-response.json")))

        Credentials emailPasscodeCredentials = new Credentials()
        emailPasscodeCredentials.setPasscode("some-email-passcode")

        AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
            .withStateHandle("stateHandle")
            .withCredentials(emailPasscodeCredentials)
            .build()
        oktaIdentityEngineResponse = remediationOption.proceed(oktaIdentityEngineClient, emailAuthenticatorAnswerChallengeRequest)

        assertThat(oktaIdentityEngineResponse, notNullValue())
        assertThat(oktaIdentityEngineResponse.remediation(), nullValue()) // no more remediation steps

        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode(), notNullValue())
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().getRel(), notNullValue())
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().getName(), notNullValue())
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().getHref(), notNullValue())
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().getMethod(), is("POST"))
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().getValue(), notNullValue())
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().parseGrantType(), is("interaction_code"))
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().parseInteractionCode(), is("Txd_5odx08kzZ_oxeEbBk8PNjI5UDnTM2P1rMCmHDyA"))
        assertThat(oktaIdentityEngineResponse.getSuccessWithInteractionCode().parseClientId(), is("0oa3jxy2kpqZs9fOU0g7"))

        wireMockServer.verify(postRequestedFor(urlEqualTo("/idp/idx/challenge/answer"))
            .withHeader("Content-Type", equalTo("application/ion+json;okta-version=1.0.0")))
        wireMockServer.resetAll()
    }

    @AfterClass
    void cleanUp() {
        wireMockServer.shutdown()
    }
}
