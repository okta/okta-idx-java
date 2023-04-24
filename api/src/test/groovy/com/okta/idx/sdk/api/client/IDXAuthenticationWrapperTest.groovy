/*
 * Copyright (c) 2021-Present, Okta, Inc.
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

import com.okta.commons.http.*
import com.okta.idx.sdk.api.config.ClientConfiguration
import com.okta.idx.sdk.api.model.AuthenticationOptions
import com.okta.idx.sdk.api.model.AuthenticationStatus
import com.okta.idx.sdk.api.model.Credentials
import com.okta.idx.sdk.api.model.IDXClientContext
import com.okta.idx.sdk.api.model.Idp
import com.okta.idx.sdk.api.model.PollInfo
import com.okta.idx.sdk.api.model.RequestContext
import com.okta.idx.sdk.api.model.UserProfile
import com.okta.idx.sdk.api.model.VerifyAuthenticatorAnswer
import com.okta.idx.sdk.api.model.VerifyAuthenticatorOptions
import com.okta.idx.sdk.api.model.VerifyChannelDataOptions
import com.okta.idx.sdk.api.request.WebAuthnRequest
import com.okta.idx.sdk.api.response.AuthenticationResponse
import org.testng.annotations.Test

import java.lang.reflect.Field

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*
import static org.mockito.ArgumentMatchers.argThat
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

class IDXAuthenticationWrapperTest {

    final MediaType mediaTypeAppIonJson = MediaType.valueOf("application/ion+json; okta-version=1.0.0")
    final MediaType mediaTypeTextHtml = MediaType.valueOf("text/html;charset=utf-8")

    @Test
    void basicIDXAuthenticationWrapperTest() {
        def clientConfig = getClientConfiguration()
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper(
                clientConfig.getIssuer(),
                clientConfig.getClientId(),
                clientConfig.getClientSecret(),
                clientConfig.getScopes(),
                clientConfig.getRedirectUri())
        IDXClient client = getInternalState(idxAuthenticationWrapper, "client") as IDXClient
        assertThat(client, notNullValue())

        ClientConfiguration config = getInternalState(client, "clientConfiguration") as ClientConfiguration
        assertThat(config, notNullValue())
        assertThat(config.issuer, is(clientConfig.getIssuer()))
        assertThat(config.clientId, is(clientConfig.getClientId()))
        assertThat(config.clientSecret, is(clientConfig.getClientSecret()))
        assertThat(config.getScopes(), is(clientConfig.getScopes()))
        assertThat(config.redirectUri, is(clientConfig.getRedirectUri()))
    }

    @Test
    void registerSuccessTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "enroll", "enroll-user-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginResponse.proceedContext)
        assertThat(newUserRegistrationResponse.getErrors(), empty())
        assertThat(newUserRegistrationResponse.getFormValues(), notNullValue())
        assertThat(newUserRegistrationResponse.getFormValues(), hasSize(1))
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().state, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle, equalTo("003Q14X7li"))
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge, notNullValue())

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)

        IDXClientContext idxClientContext = newUserRegistrationResponse.getProceedContext().getClientContext()
        assertThat(idxClientContext.state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(idxClientContext.interactionHandle,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle))
        assertThat(idxClientContext.codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))
        assertThat(idxClientContext.codeChallenge,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge))

        setMockResponse(requestExecutor, "introspect", "enroll-user-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "enroll/new", "enroll-profile-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.register(newUserRegistrationResponse.getProceedContext(), getUserProfile(), null)
        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(authenticationResponse.getProceedContext().getClientContext().interactionHandle,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle))
        assertThat(authenticationResponse.getProceedContext().getClientContext().codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))
        assertThat(authenticationResponse.getProceedContext().getClientContext().codeChallenge,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge))
    }

    @Test
    void registerFailTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "enroll", "enroll-user-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginResponse.proceedContext)
        assertThat(newUserRegistrationResponse.getErrors(), empty())
        assertThat(newUserRegistrationResponse.getFormValues(), notNullValue())

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "enroll-user-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "enroll/new", "enroll-profile-error-response", 400, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.register(newUserRegistrationResponse.getProceedContext(), getUserProfile(), null)
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(), nullValue())
        assertThat(authenticationResponse.getErrors(), notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItems(
                "Provided value for property 'Email' does not match required pattern",
                "'Email' must be in the form of an email address"
        ))
    }

    @Test
    void verifyEmailSuccessResponseTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)

        AuthenticationTransaction introspectTransaction = AuthenticationTransaction.create(idxClient)
        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("correct_code")

        setMockResponse(requestExecutor, "introspect", "challenge-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "challenge/answer", "answer-challenge-identify-first-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.verifyAuthenticator(
                new ProceedContext(introspectTransaction.clientContext,
                        introspectTransaction.getStateHandle(), "/challenge/answer", null, false, null, null, null, null, null),
                verifyAuthenticatorOptions
        )

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_SELECTION))
    }

    @Test
    void verifyEmailErrorResponseTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)

        AuthenticationTransaction introspectTransaction = AuthenticationTransaction.create(idxClient)
        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("wrong_code")

        setMockResponse(requestExecutor, "introspect", "challenge-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "challenge/answer", "challenge-error-response", 401, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.verifyAuthenticator(
                new ProceedContext(introspectTransaction.clientContext,
                        introspectTransaction.getStateHandle(), "/challenge/answer", null, false, null, null, null, null, null),
                verifyAuthenticatorOptions
        )

        assertThat(authenticationResponse.getErrors(), hasSize(1))
        assertThat(authenticationResponse.getErrors().get(0), equalTo("Invalid code. Try again."))
    }

    @Test
    void recoverPasswordTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "recover", "recover-transaction-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "identify-response", 200, mediaTypeAppIonJson)

        String userEmail = "joe.coder" + (new Random()).nextInt(1000) + "@example.com"

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.recoverPassword(userEmail, beginResponse.proceedContext)
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                equalTo(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION))

        setMockResponse(requestExecutor, "introspect", "challenge-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "recover", "answer-challenge-response", 200, mediaTypeAppIonJson)

        List<Authenticator> authenticators = authenticationResponse.getAuthenticators()
        assertThat(authenticators, notNullValue())
        assertThat(authenticators, hasItem(
                hasProperty("label", is("Email")))
        )
    }

    @Test
    void recoverPasswordIdentifyFirstTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-identify-first-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "challenge", "identify-first-success-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "recover", "recover-identify-first-response", 200, mediaTypeAppIonJson)

        String userEmail = "joe.coder" + (new Random()).nextInt(1000) + "@example.com"

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.recoverPassword(userEmail, beginResponse.proceedContext)
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                equalTo(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION))
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Email")))
        )
    }

    @Test
    void authenticateOneStepSuccessTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "success-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "token", "token-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getTokenResponse(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getScope(), is("openid email"))
        assertThat(authenticationResponse.getTokenResponse().getTokenType(), is("Bearer"))
        assertThat(authenticationResponse.getTokenResponse().getExpiresIn(), is(3600))
        assertThat(authenticationResponse.getTokenResponse().getAccessToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getRefreshToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getIdToken(), notNullValue())
    }

    @Test
    void authenticateOneStepFailTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "identify-error-response", 400, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("Authentication failed"))
    }

    @Test
    void authenticateIdentifyFirstSuccessTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-identify-first-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "identify-first-success-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", "challenge-identify-first-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "token", "token-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )

        assertThat(beginResponse.proceedContext.isIdentifierFirstFlow(), is(true)) // password not required
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getTokenResponse(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getScope(), is("openid email"))
        assertThat(authenticationResponse.getTokenResponse().getTokenType(), is("Bearer"))
        assertThat(authenticationResponse.getTokenResponse().getExpiresIn(), is(3600))
        assertThat(authenticationResponse.getTokenResponse().getAccessToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getRefreshToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getIdToken(), notNullValue())
    }

    @Test
    void authenticateWithoutPasswordSuccessTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-identify-first-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "identify-first-success-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", "challenge-identify-first-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "token", "token-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username"), beginResponse.proceedContext
        )

        assertThat(beginResponse.proceedContext.isIdentifierFirstFlow(), is(true)) // password not required
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION))
    }

    @Test
    void beginTransactionWithAndWithoutActivationTokenTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        // test with activation token

        setMockResponseOnlyIfBodyParamMatches(requestExecutor, "interact", "activation_token", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-with-activation-token-response", 200, mediaTypeAppIonJson)

        final RequestContext requestContext = new RequestContext()
        requestContext.setDeviceToken("test_x_device_token")

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.beginUserActivation("activation-token", requestContext)

        assertThat(beginResponse, notNullValue())
        assertThat(beginResponse.getErrors(), empty())
        assertThat(beginResponse.getAuthenticationStatus(), is(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_SELECTION))

        // test without activation token

        setMockResponseOnlyIfBodyParamWontMatch(requestExecutor, "interact", "activation_token", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)

        beginResponse = idxAuthenticationWrapper.begin()

        assertThat(beginResponse, notNullValue())
        assertThat(beginResponse.getErrors(), empty())
        assertThat(beginResponse.getAuthenticationStatus(), is(AuthenticationStatus.UNKNOWN))
    }

    @Test
    void authenticateIdentifyFirstFailTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-identify-first-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "identify-first-error-response", 400, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("Password is incorrect"))
    }

    @Test
    void authenticateIdentifyFirstFactorSuccessTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-identify-first-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "identify-first-success-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", "challenge-identify-first-factor-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION)
        )
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Email")))
        )
    }

    @Test
    void authenticateIdentifyFirstFactorPasswordSuccessTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-identify-first-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "identify-first-factor-password-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "challenge", "challenge-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", "challenge-identify-first-factor-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION)
        )
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Email")))
        )
    }

    @Test
    void testVerifyEmailToken() {
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "verify", "verify-email-token-response", 200, mediaTypeTextHtml)
        Response response = idxAuthenticationWrapper.verifyEmailToken("some-token")

        assertThat(response, notNullValue())
        assertThat(response.getHttpStatus(), equalTo(200))
        assertThat(response.getHeaders().getContentType(), equalTo(mediaTypeTextHtml))
    }

    @Test
    void testGetPollInfo() {
        def scenario = "scenario_6_1_2"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION))
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Email")))
        )

        Authenticator emailAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "challenge", scenario + "/challenge-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), emailAuthenticator)

        assertThat(authenticationResponse, notNullValue())

        PollInfo pollInfo = idxAuthenticationWrapper.getPollInfo(authenticationResponse)

        assertThat(pollInfo, notNullValue())
        assertThat(pollInfo.getHref(), equalTo("https://foo.oktapreview.com/idp/idx/challenge/poll"))
        assertThat(pollInfo.getRefresh(), notNullValue())
        assertThat(pollInfo.getRefresh().getSeconds(), is(4L))
    }

    @Test
    void pollTest() {
        def scenario = "scenario_6_1_2"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "poll", "poll-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION))
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Email")))
        )

        Authenticator emailAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "challenge", scenario + "/challenge-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), emailAuthenticator)

        assertThat(authenticationResponse, notNullValue())

        PollInfo pollInfo = idxAuthenticationWrapper.getPollInfo(authenticationResponse)

        assertThat(pollInfo, notNullValue())
        assertThat(pollInfo.getHref(), equalTo("https://foo.oktapreview.com/idp/idx/challenge/poll"))
        assertThat(pollInfo.getRefresh(), notNullValue())
        assertThat(pollInfo.getRefresh().getSeconds(), is(4L))

        AuthenticationResponse pollResponse = idxAuthenticationWrapper.poll(authenticationResponse.getProceedContext())

        assertThat(pollResponse, notNullValue())
        assertThat(pollResponse.getErrors(), empty())
        assertThat(pollResponse.getProceedContext(), notNullValue())
        assertThat(pollResponse.getProceedContext().getHref(), equalTo("https://foo.oktapreview.com/idp/idx/challenge/answer"))
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION))
    }

    @Test
    void cancelTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "cancel", "cancel-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.cancel(beginResponse.proceedContext)

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments(), nullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.UNKNOWN)
        )
    }

    @Test(testName = "User logs in with password")
    void testLoginWithCorrectUsernamePassword() {

        def scenario = "scenario_1_1_1"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", scenario + "/answer-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "token", scenario + "/token-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "userinfo", scenario + "/userinfo-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("mary@example.com", "superSecret".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.SUCCESS)
        )
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test(testName = "User does not know username")
    void testLoginWithIncorrectUsername() {

        def scenario = "scenario_1_1_2"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", scenario + "/answer-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("mary@unknown.com", "superSecret".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("There is no account with the Username mary@unknown.com."))
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.UNKNOWN)
        )
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test(testName = "User does not know the password")
    void testLoginWithIncorrectPassword() {

        def scenario = "scenario_1_1_3"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", scenario + "/answer-response", 400, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("mary@example.com", "wrong".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("Password is incorrect"))
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test(testName = "User is not assigned to the application")
    void testLoginWithUserUnassignedToApp() {

        def scenario = "scenario_1_1_4"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", scenario + "/answer-response", 400, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("mary@example.com", "superSecret".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("User is not assigned to this application"))
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test(testName = "User account is suspended")
    void testLoginWithSuspendedUserAccount() {

        def scenario = "scenario_1_1_5"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", scenario + "/answer-response", 400, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("mary@example.com", "superSecret".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("Authentication failed"))
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test(testName = "User account is locked")
    void testLoginWithLockedUserAccount() {

        def scenario = "scenario_1_1_6"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", scenario + "/answer-response", 400, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("mary@example.com", "superSecret".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("This factor is suspended for your account due to too many failed attempts"))
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test(testName = "User account is deactivated")
    void testLoginWithDeactivatedUserAccount() {

        def scenario = "scenario_1_1_7"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", scenario + "/answer-response", 400, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("mary@example.com", "superSecret".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("Authentication failed"))
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test(testName = "User logs in with password and security question")
    void testLoginWithPasswordAndSecurityQuestion() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "challenge", "challenge-security-question-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "answer", "answer-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "token", "token-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("some.user@example.com", "superSecret".toCharArray()), beginResponse.proceedContext
        )

        Optional<Authenticator> authenticator = authenticationResponse.getAuthenticators().stream()
                .filter(x -> "security_question" == x.type).findFirst()
        assertThat(authenticator.isPresent(), is(true))

        authenticationResponse = idxAuthenticationWrapper
                .selectAuthenticator(authenticationResponse.proceedContext, authenticator.get())

        authenticationResponse = idxAuthenticationWrapper.verifyAuthenticator(
                authenticationResponse.proceedContext,
                new VerifyAuthenticatorAnswer("Answer", null, "first_computer_game")
        )

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.SUCCESS)
        )
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test(testName = "User tries to reset a password with the wrong email")
    void testResetPasswordWithWrongEmail() {

        def scenario = "scenario_3_1_2"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "recover", scenario + "/recover-response", 400, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("Mary@unknown.com", "superSecret".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("There is no account with the Username Mary@unknown.com."))
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test(testName = "User signs up for an account with Password, setups up required Email factor, then skips optional SMS")
    void testSelfServiceRegistrationWithPasswordAndEmailAndSkipOptionalSms() {

        def scenario = "scenario_4_1_1"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "enroll", scenario + "/enroll-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginResponse.proceedContext)
        assertThat(newUserRegistrationResponse.getErrors(), empty())
        assertThat(newUserRegistrationResponse.getFormValues(), notNullValue())
        assertThat(newUserRegistrationResponse.getFormValues(), hasSize(1))
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().state, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle, equalTo("029ZAB"))
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge, notNullValue())

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)

        IDXClientContext idxClientContext = newUserRegistrationResponse.getProceedContext().getClientContext()
        assertThat(idxClientContext.state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(idxClientContext.interactionHandle,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle))
        assertThat(idxClientContext.codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))
        assertThat(idxClientContext.codeChallenge,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge))

        setMockResponse(requestExecutor, "introspect", scenario + "/enroll-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "enroll/new", scenario + "/enroll-new-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.register(newUserRegistrationResponse.getProceedContext(), getUserProfile(), null)
        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(authenticationResponse.getProceedContext().getClientContext().interactionHandle,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle))
        assertThat(authenticationResponse.getProceedContext().getClientContext().codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))
        assertThat(authenticationResponse.getProceedContext().getClientContext().codeChallenge,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge))

        Authenticator passwordAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-password-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), passwordAuthenticator)

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-password-response", 200, mediaTypeAppIonJson)

        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("Abcd12cd134")

        authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        Authenticator emailAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-email-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), emailAuthenticator)

        verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("471537")

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-email-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        setMockResponse(requestExecutor, "idp/idx/skip", scenario + "/skip-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "oauth2/v1/token", scenario + "/token-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "oauth2/default/v1/userinfo", scenario + "/user-info-response", 200, mediaTypeAppIonJson)

        authenticationResponse = idxAuthenticationWrapper.skipAuthenticatorEnrollment(authenticationResponse.getProceedContext())

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getTokenResponse(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getScope(), is("openid profile offline_access"))
        assertThat(authenticationResponse.getTokenResponse().getTokenType(), is("Bearer"))
        assertThat(authenticationResponse.getTokenResponse().getExpiresIn(), is(3600))
        assertThat(authenticationResponse.getTokenResponse().getAccessToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getRefreshToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getIdToken(), notNullValue())
    }

    @Test(testName = "User signs up for an account with Password, setups up required Email factor, AND sets up optional SMS")
    void testSelfServiceRegistrationWithPasswordAndEmailAndSetupOptionalSms() {

        def scenario = "scenario_4_1_2"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "enroll", scenario + "/enroll-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginResponse.proceedContext)
        assertThat(newUserRegistrationResponse.getErrors(), empty())
        assertThat(newUserRegistrationResponse.getFormValues(), notNullValue())
        assertThat(newUserRegistrationResponse.getFormValues(), hasSize(1))
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().state, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle, equalTo("029ZAB"))
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge, notNullValue())

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)

        IDXClientContext idxClientContext = newUserRegistrationResponse.getProceedContext().getClientContext()
        assertThat(idxClientContext.state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(idxClientContext.interactionHandle,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle))
        assertThat(idxClientContext.codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))
        assertThat(idxClientContext.codeChallenge,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge))

        setMockResponse(requestExecutor, "introspect", scenario + "/enroll-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "enroll/new", scenario + "/enroll-new-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.register(newUserRegistrationResponse.getProceedContext(), getUserProfile(), null)
        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(authenticationResponse.getProceedContext().getClientContext().interactionHandle,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle))
        assertThat(authenticationResponse.getProceedContext().getClientContext().codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))
        assertThat(authenticationResponse.getProceedContext().getClientContext().codeChallenge,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge))

        Authenticator passwordAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-password-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), passwordAuthenticator)

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-password-response", 200, mediaTypeAppIonJson)

        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("Abcd12cd134")

        authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        Authenticator emailAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-email-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), emailAuthenticator)

        verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("471537")

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-email-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        Authenticator phoneAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-phone-response", 200, mediaTypeAppIonJson)

        Authenticator.Factor smsFactor = new Authenticator.Factor(
                phoneAuthenticator.getId(), "sms", null, phoneAuthenticator.getLabel(), null
        )

        authenticationResponse = idxAuthenticationWrapper.selectFactor(authenticationResponse.getProceedContext(), smsFactor)

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-phone-number-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.submitPhoneAuthenticator(authenticationResponse.getProceedContext(), "14021234567", smsFactor)

        setMockResponse(requestExecutor, "oauth2/v1/token", scenario + "/token-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "oauth2/default/v1/userinfo", scenario + "/user-info-response", 200, mediaTypeAppIonJson)

        verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("134165")

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-phone-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getTokenResponse(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getScope(), is("openid profile offline_access"))
        assertThat(authenticationResponse.getTokenResponse().getTokenType(), is("Bearer"))
        assertThat(authenticationResponse.getTokenResponse().getExpiresIn(), is(3600))
        assertThat(authenticationResponse.getTokenResponse().getAccessToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getRefreshToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getIdToken(), notNullValue())
    }

    @Test(testName = "User signs up for an account with Password, sets up required Email factor, AND sets up optional SMS with an invalid phone number")
    void testSelfServiceRegistrationWithPasswordAndEmailAndSetupOptionalSmsWithInvalidPhoneNumber() {

        def scenario = "scenario_4_1_4"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "enroll", scenario + "/enroll-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginResponse.proceedContext)
        assertThat(newUserRegistrationResponse.getErrors(), empty())
        assertThat(newUserRegistrationResponse.getFormValues(), notNullValue())
        assertThat(newUserRegistrationResponse.getFormValues(), hasSize(1))
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().state, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle, equalTo("029ZAB"))
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge, notNullValue())

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)

        IDXClientContext idxClientContext = newUserRegistrationResponse.getProceedContext().getClientContext()
        assertThat(idxClientContext.state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(idxClientContext.interactionHandle,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle))
        assertThat(idxClientContext.codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))
        assertThat(idxClientContext.codeChallenge,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge))

        setMockResponse(requestExecutor, "introspect", scenario + "/enroll-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "enroll/new", scenario + "/enroll-new-response", 200, mediaTypeAppIonJson)

        Credentials credentials = new Credentials()
        credentials.setPasscode("dummy".toCharArray())
        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.register(newUserRegistrationResponse.getProceedContext(), getUserProfile(), credentials)
        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(authenticationResponse.getProceedContext().getClientContext().interactionHandle,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle))
        assertThat(authenticationResponse.getProceedContext().getClientContext().codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))
        assertThat(authenticationResponse.getProceedContext().getClientContext().codeChallenge,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge))

        Authenticator passwordAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-password-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), passwordAuthenticator)

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-password-response", 200, mediaTypeAppIonJson)

        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("Abcd12cd134")

        authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        Authenticator emailAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-email-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), emailAuthenticator)

        verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("471537")

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-email-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        ProceedContext proceedContext = authenticationResponse.getProceedContext()

        Authenticator phoneAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-phone-response", 200, mediaTypeAppIonJson)

        Authenticator.Factor smsFactor = new Authenticator.Factor(
                phoneAuthenticator.getId(), "sms", null, phoneAuthenticator.getLabel(), null
        )

        idxAuthenticationWrapper.selectFactor(authenticationResponse.getProceedContext(), smsFactor)

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-phone-number-response", 200, mediaTypeAppIonJson)

        // invalid phone number
        authenticationResponse =
                idxAuthenticationWrapper.submitPhoneAuthenticator(proceedContext, "123", smsFactor)

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("Unable to initiate factor enrollment: Invalid Phone Number."))
    }

    @Test(testName = "User Logs in with Social IDP")
    void testSocialIdpLogin() {

        def scenario = "scenario_5_1_1"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        assertThat(beginResponse, notNullValue())
        assertThat(beginResponse.getAuthenticationStatus(), is(AuthenticationStatus.UNKNOWN))

        List<Idp> idpList = beginResponse.getIdps()
        assertThat(idpList, hasSize(1))
        assertThat(idpList.first().type, is("GOOGLE"))
        assertThat(idpList.first().href, is("https://foo.oktapreview.com/oauth2/ausko2zk1B3kDU2d65d6/v1/authorize?client_id=0oal2s4yhspmifyt65d6&request_uri=urn:okta:bGNlQkY4NzltNXRWeHNheUlOVVJwOWN2Rk1DSElfS0JQVUlSaE5LWlQtTTowb2Fyc2Q5dWZmUjh0alNBTDVkNg"))
    }

    @Test(testName = "2FA Login with Email")
    void test2FAWithEmail() {

        def scenario = "scenario_6_1_2"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION)
        )
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Phone")))
        )
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Email")))
        )

        assertThat(authenticationResponse.getAuthenticatorEnrollments(), notNullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues(), hasSize(2))

        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(0).getType(), is("email"))
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(0).getProfile(), notNullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(0).getProfile().getEmail(), is("j***8@gmail.com"))
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(0).getMethods(), notNullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(0).getMethods().length, is(1))

        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(1).getType(), is("phone"))
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(1).getProfile(), notNullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(1).getProfile().getPhoneNumber(), is("+1 XXX-XXX-0364"))
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(1).getMethods(), notNullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(1).getMethods().length, is(2))

        Authenticator emailAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "challenge", scenario + "/challenge-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), emailAuthenticator)

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION)
        )

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-response", 200, mediaTypeAppIonJson)

        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("Abcd12cd134")

        setMockResponse(requestExecutor, "token", scenario + "/token-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "userinfo", scenario + "/user-info-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getTokenResponse(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getScope(), is("openid profile offline_access"))
        assertThat(authenticationResponse.getTokenResponse().getTokenType(), is("Bearer"))
        assertThat(authenticationResponse.getTokenResponse().getExpiresIn(), is(3600))
        assertThat(authenticationResponse.getTokenResponse().getAccessToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getRefreshToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getIdToken(), notNullValue())
    }

    @Test(testName = "User enters a wrong verification code")
    void test2FAWithEmailAndWrongVerificationCode() {

        def scenario = "scenario_6_1_3"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION)
        )
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Phone")))
        )
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Email")))
        )

        assertThat(authenticationResponse.getAuthenticatorEnrollments(), notNullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues(), hasSize(2))

        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(0).getType(), is("email"))
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(0).getProfile(), notNullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(0).getProfile().getEmail(), is("j***8@gmail.com"))
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(0).getMethods(), notNullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(0).getMethods().length, is(1))

        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(1).getType(), is("phone"))
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(1).getProfile(), notNullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(1).getProfile().getPhoneNumber(), is("+1 XXX-XXX-0364"))
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(1).getMethods(), notNullValue())
        assertThat(authenticationResponse.getAuthenticatorEnrollments().getValues().get(1).getMethods().length, is(2))

        assertThat(authenticationResponse.getUser(), notNullValue())
        assertThat(authenticationResponse.getUser().getValue(), notNullValue())
        assertThat(authenticationResponse.getUser().getValue().getId(), is("00unr4gf3Tg9WyAMW5d6"))
        assertThat(authenticationResponse.getUser().getValue().getIdentifier(), is("email"))
        assertThat(authenticationResponse.getUser().getValue().getProfile(), notNullValue())
        assertThat(authenticationResponse.getUser().getValue().getProfile().getFields(), notNullValue())
        assertThat(authenticationResponse.getUser().getValue().getProfile().getFields().get("firstName"), is("John"))
        assertThat(authenticationResponse.getUser().getValue().getProfile().getFields().get("lastName"), is("Ferguson"))
        assertThat(authenticationResponse.getUser().getValue().getProfile().getFields().get("timeZone"), is("America/Los_Angeles"))
        assertThat(authenticationResponse.getUser().getValue().getProfile().getFields().get("locale"), is("en_US"))

        Authenticator emailAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "challenge", scenario + "/challenge-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), emailAuthenticator)

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION)
        )

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-response", 400, mediaTypeAppIonJson)

        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("wrong-code")

        authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem("Invalid code. Try again."))
    }

    @Test(testName = "Enroll in SMS Factor prompt when authenticating")
    void testMFAWithSMSFactorPromptWhenAuthenticating() {

        def scenario = "scenario_6_2_1"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_SELECTION)
        )
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Phone")))
        )

        Optional<Authenticator> authenticator = authenticationResponse.getAuthenticators()
                .stream().filter({ auth -> (auth.label == "Phone") }).findFirst()
        assertThat("No Phone authenticator found", authenticator.isPresent())
        setMockResponse(requestExecutor, "credential/enroll", scenario + "/challenge-response", 200, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.selectAuthenticator(
                authenticationResponse.proceedContext, authenticator.get()
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_DATA)
        )

        Optional<Authenticator.Factor> factor = authenticator.get().getFactors()
                .stream().filter({ factor -> (factor.label == "SMS") }).findFirst()
        assertThat("No SMS factor found", factor.isPresent())
        setMockResponse(requestExecutor, "credential/enroll", scenario + "/enroll-response", 200, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.submitPhoneAuthenticator(
                authenticationResponse.proceedContext, "+11234567890", factor.get()
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT)
        )

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/answer-challenge-sms-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "token", scenario + "/token-response", 200, mediaTypeAppIonJson)
        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("123456")
        authenticationResponse = idxAuthenticationWrapper.verifyAuthenticator(
                authenticationResponse.proceedContext, verifyAuthenticatorOptions
        )

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getTokenResponse(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getScope(), is("offline_access openid profile email"))
        assertThat(authenticationResponse.getTokenResponse().getTokenType(), is("Bearer"))
        assertThat(authenticationResponse.getTokenResponse().getExpiresIn(), is(3600))
        assertThat(authenticationResponse.getTokenResponse().getAccessToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getRefreshToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getIdToken(), notNullValue())
    }

    @Test(testName = "2FA Login with SMS")
    void test2FALoginWithSMS() {

        def scenario = "scenario_6_2_2"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION_DATA)
        )
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Phone")))
        )

        Optional<Authenticator> authenticator = authenticationResponse.getAuthenticators()
                .stream().filter({ auth -> (auth.label == "Phone") }).findFirst()
        assertThat("No Phone authenticator found", authenticator.isPresent())
        setMockResponse(requestExecutor, "challenge", scenario + "/challenge-response", 200, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.selectAuthenticator(
                authenticationResponse.proceedContext, authenticator.get()
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION)
        )

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/answer-challenge-sms-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "token", scenario + "/token-response", 200, mediaTypeAppIonJson)
        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("123456")
        authenticationResponse = idxAuthenticationWrapper.verifyAuthenticator(
                authenticationResponse.proceedContext, verifyAuthenticatorOptions
        )

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getTokenResponse(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getScope(), is("offline_access openid profile email"))
        assertThat(authenticationResponse.getTokenResponse().getTokenType(), is("Bearer"))
        assertThat(authenticationResponse.getTokenResponse().getExpiresIn(), is(3600))
        assertThat(authenticationResponse.getTokenResponse().getAccessToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getRefreshToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getIdToken(), notNullValue())
    }

    @Test(testName = "Enroll with Invalid Phone Number")
    void testMFAWithInvalidPhoneNumber() {

        def scenario = "scenario_6_2_3"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_SELECTION)
        )
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Phone")))
        )

        Optional<Authenticator> authenticator = authenticationResponse.getAuthenticators()
                .stream().filter({ auth -> (auth.label == "Phone") }).findFirst()
        assertThat("No Phone authenticator found", authenticator.isPresent())
        setMockResponse(requestExecutor, "credential/enroll", scenario + "/challenge-response", 200, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.selectAuthenticator(
                authenticationResponse.proceedContext, authenticator.get()
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_DATA)
        )

        Optional<Authenticator.Factor> factor = authenticator.get().getFactors()
                .stream().filter({ factor -> (factor.label == "SMS") }).findFirst()
        assertThat("No SMS factor found", factor.isPresent())
        setMockResponse(requestExecutor, "credential/enroll", scenario + "/enroll-invalid-response", 400, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.submitPhoneAuthenticator(
                authenticationResponse.proceedContext, "+333333333333", factor.get()
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem(
                "Unable to initiate factor enrollment: Invalid Phone Number."
        ))
    }

    @Test(testName = "User enters a wrong verification code on verify")
    void testMFAWithInvalidCodeFromSMS() {

        def scenario = "scenario_6_2_4"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_SELECTION)
        )
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Phone")))
        )

        Optional<Authenticator> authenticator = authenticationResponse.getAuthenticators()
                .stream().filter({ auth -> (auth.label == "Phone") }).findFirst()
        assertThat("No Phone authenticator found", authenticator.isPresent())
        setMockResponse(requestExecutor, "credential/enroll", scenario + "/challenge-response", 200, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.selectAuthenticator(
                authenticationResponse.proceedContext, authenticator.get()
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_DATA)
        )

        Optional<Authenticator.Factor> factor = authenticator.get().getFactors()
                .stream().filter({ factor -> (factor.label == "SMS") }).findFirst()
        assertThat("No SMS factor found", factor.isPresent())
        setMockResponse(requestExecutor, "credential/enroll", scenario + "/enroll-response", 200, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.submitPhoneAuthenticator(
                authenticationResponse.proceedContext, "+11234567890", factor.get()
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT)
        )

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/answer-challenge-sms-invalid-response", 401, mediaTypeAppIonJson)
        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("123456")
        authenticationResponse = idxAuthenticationWrapper.verifyAuthenticator(
                authenticationResponse.proceedContext, verifyAuthenticatorOptions
        )

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), notNullValue())
        assertThat(authenticationResponse.getErrors(), hasItem(
                "Invalid code. Try again."
        ))
    }

    @Test(testName = "User signs up for an account and registers Password and WebAuthn")
    void testEnrollWithPasswordAndWebauthn() {

        def scenario = "scenario_10_2_1"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "enroll", scenario + "/enroll-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginResponse.proceedContext)
        assertThat(newUserRegistrationResponse.getErrors(), empty())
        assertThat(newUserRegistrationResponse.getFormValues(), notNullValue())
        assertThat(newUserRegistrationResponse.getFormValues(), hasSize(1))
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().state, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle, equalTo("029ZAB"))
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier, notNullValue())
        assertThat(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge, notNullValue())

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)

        IDXClientContext idxClientContext = newUserRegistrationResponse.getProceedContext().getClientContext()
        assertThat(idxClientContext.state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(idxClientContext.interactionHandle,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle))
        assertThat(idxClientContext.codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))
        assertThat(idxClientContext.codeChallenge,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge))

        setMockResponse(requestExecutor, "introspect", scenario + "/enroll-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "enroll/new", scenario + "/enroll-new-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse =
                idxAuthenticationWrapper.register(newUserRegistrationResponse.getProceedContext(), getUserProfile(), null)
        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(authenticationResponse.getProceedContext().getClientContext().interactionHandle,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().interactionHandle))
        assertThat(authenticationResponse.getProceedContext().getClientContext().codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))
        assertThat(authenticationResponse.getProceedContext().getClientContext().codeChallenge,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeChallenge))

        Authenticator passwordAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-password-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), passwordAuthenticator)

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-password-response", 200, mediaTypeAppIonJson)

        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("Abcd12cd134")

        authenticationResponse =
                idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

       // Authenticator filteredWebauthn = authenticationResponse.authenticators.stream().filter(f -> f.label == "Security Key or Biometric")

        Authenticator webauthnAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-webauthn-response", 200, mediaTypeAppIonJson)

        authenticationResponse =
                idxAuthenticationWrapper.selectAuthenticator(authenticationResponse.getProceedContext(), webauthnAuthenticator)

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-webauthn-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "token", scenario + "/token-response", 200, mediaTypeAppIonJson)

        WebAuthnRequest webAuthnRequest = new WebAuthnRequest()
        webAuthnRequest.attestation = "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEgwRgIhAPxn7aZG1m65SYOBt+bXDByFnunKks6pH1EzOdf3kF+bAiEA7fs/XAbUlzoYTWC2OagodVzCwGTSuzKDgHsw5eYPBKpoYXV0aERhdGFY0fSEN0f/X2IQM9Djsj4XeIrbzuOswjVu3W9DCDmxtPhwRWFf0CetzgACNbzGCmSLCyXx8FUDAE0BLQFPAUOb0JLoWAzzK7Mos3dOH+sYh5lWS7MSC7E3fc5AIQVLZsfULs4O4idie31KC9QehVIXcygvOcsdenOlGPAEuktKd++T6Zp+Z6UBAgMmIAEhWCCVSkj7Fkim/hXWVqnLP/oAo4m/+bXfEyfoK+S2fUoQBSJYINfXOAFm0sUWemdeTMaMuQnSDTfz6spbn6sXxtXGtJoL"
        webAuthnRequest.clientData = "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiWjV5MlNEbVYwejZNUmtvZEIzN3FqMmlZZUhrIiwib3JpZ2luIjoiaHR0cHM6Ly9qYXZhLXNkay5va3RhcHJldmlldy5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
        authenticationResponse = idxAuthenticationWrapper.verifyWebAuthn(
                authenticationResponse.proceedContext, webAuthnRequest
        )

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getTokenResponse(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getScope(), is("offline_access openid profile email"))
        assertThat(authenticationResponse.getTokenResponse().getTokenType(), is("Bearer"))
        assertThat(authenticationResponse.getTokenResponse().getExpiresIn(), is(3600))
        assertThat(authenticationResponse.getTokenResponse().getAccessToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getRefreshToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getIdToken(), notNullValue())
    }

    @Test(testName = "User logs into the Sample App with Password and WebAuthn")
    void testLoginWithPasswordAndWebauthn() {

        def scenario = "scenario_10_2_2"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", scenario + "/interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", scenario + "/introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", scenario + "/identify-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password".toCharArray()), beginResponse.proceedContext
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION)
        )
        assertThat(authenticationResponse.getAuthenticators(), notNullValue())
        assertThat(authenticationResponse.getAuthenticators(),
                hasItem(hasProperty("label", is("Security Key or Biometric")))
        )

        Optional<Authenticator> authenticator = authenticationResponse.getAuthenticators()
                .stream().filter({ auth -> (auth.label == "Security Key or Biometric") }).findFirst()
        assertThat("No Security Key or Biometric authenticator found", authenticator.isPresent())
        setMockResponse(requestExecutor, "challenge", scenario + "/challenge-response", 200, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.selectAuthenticator(
                authenticationResponse.proceedContext, authenticator.get()
        )
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                is(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION)
        )

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/webauthn-answer-challenge-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "token", scenario + "/token-response", 200, mediaTypeAppIonJson)

        WebAuthnRequest webauthnRequest = new WebAuthnRequest()
        webauthnRequest.authenticatorData = "9IQ3R/9fYhAz0OOyPhd4itvO46zCNW7db0MIObG0+HAFYV/DeQ=="
        webauthnRequest.clientData = "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0IiwiY2hhbGxlbmdlIjoiZEZMcjVJRXBlTjVyaTNvLWpITnYtRjduYVRjIiwib3JpZ2luIjoiaHR0cHM6Ly9qYXZhLXNkay5va3RhcHJldmlldy5jb20iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
        webauthnRequest.signatureData = "MEYCIQCYxvAygX/ItkItMpR43mvtLC4juL7X5DO20+p/oEePfwIhAJjT5pq0fkq50o+AGL3uLftPjiBDo95gxsG3qoinwucu"
        authenticationResponse = idxAuthenticationWrapper.verifyWebAuthn(
                authenticationResponse.proceedContext, webauthnRequest
        )

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getTokenResponse(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getScope(), is("offline_access openid profile email"))
        assertThat(authenticationResponse.getTokenResponse().getTokenType(), is("Bearer"))
        assertThat(authenticationResponse.getTokenResponse().getExpiresIn(), is(3600))
        assertThat(authenticationResponse.getTokenResponse().getAccessToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getRefreshToken(), notNullValue())
        assertThat(authenticationResponse.getTokenResponse().getIdToken(), notNullValue())
    }

    @Test
    void enrollWithOktaVerifyQrCodeTest() {

        def scenario = "scenario_10_3_1"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "enroll", "enroll-user-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginResponse.proceedContext)
        assertThat(newUserRegistrationResponse.getErrors(), empty())
        assertThat(newUserRegistrationResponse.getFormValues(), notNullValue())

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)

        IDXClientContext idxClientContext = newUserRegistrationResponse.getProceedContext().getClientContext()

        assertThat(idxClientContext.state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(idxClientContext.codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))

        setMockResponse(requestExecutor, "introspect", "enroll-user-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "enroll/new", "enroll-profile-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper
                .register(newUserRegistrationResponse.getProceedContext(), getUserProfile(), null)

        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))

        Authenticator passwordAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-password-response", 200, MediaType.APPLICATION_JSON)
        authenticationResponse = idxAuthenticationWrapper
                .selectAuthenticator(authenticationResponse.getProceedContext(), passwordAuthenticator)

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-password-response", 200, mediaTypeAppIonJson)
        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("Abcd1234")
        authenticationResponse = idxAuthenticationWrapper
                .verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        Optional<Authenticator> authenticator = authenticationResponse.getAuthenticators()
                .stream().filter({ auth -> (auth.label == "Okta Verify") }).findFirst()
        assertThat("No Okta Verify authenticator found", authenticator.isPresent())

        Optional<Authenticator.Factor> factor = authenticator.get().getFactors()
                .stream().filter({ factor -> (factor.label == "QRCODE") }).findFirst()
        assertThat("No QRCODE factor found", factor.isPresent())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/enroll-response", 200, MediaType.APPLICATION_JSON)
        authenticationResponse = idxAuthenticationWrapper.selectFactor(
                authenticationResponse.proceedContext, factor.get()
        )
        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(authenticationResponse.getAuthenticationStatus(),
                equalTo(AuthenticationStatus.AWAITING_POLL_ENROLLMENT))
        assertThat(authenticationResponse.getContextualData().getQrcode().getHref(),
                startsWith("data:image/png;base64"))

        setMockResponse(requestExecutor, "challenge/poll", scenario + "/poll-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "token", scenario + "/token-response", 200, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.poll(authenticationResponse.proceedContext)

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test
    void enrollWithOktaVerifySmsTest() {

        def scenario = "scenario_10_3_2"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "enroll", "enroll-user-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginResponse.proceedContext)
        assertThat(newUserRegistrationResponse.getErrors(), empty())
        assertThat(newUserRegistrationResponse.getFormValues(), notNullValue())

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)

        IDXClientContext idxClientContext = newUserRegistrationResponse.getProceedContext().getClientContext()

        assertThat(idxClientContext.state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(idxClientContext.codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))

        setMockResponse(requestExecutor, "introspect", "enroll-user-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "enroll/new", "enroll-profile-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper
                .register(newUserRegistrationResponse.getProceedContext(), getUserProfile(), null)

        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))

        Authenticator passwordAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-password-response", 200, MediaType.APPLICATION_JSON)
        authenticationResponse = idxAuthenticationWrapper
                .selectAuthenticator(authenticationResponse.getProceedContext(), passwordAuthenticator)

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-password-response", 200, mediaTypeAppIonJson)
        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("Abcd1234")
        authenticationResponse = idxAuthenticationWrapper
                .verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        Optional<Authenticator> authenticator = authenticationResponse.getAuthenticators()
                .stream().filter({ auth -> (auth.label == "Okta Verify") }).findFirst()
        assertThat("No Okta Verify authenticator found", authenticator.isPresent())

        Optional<Authenticator.Factor> factor = authenticator.get().getFactors()
                .stream().filter({ factor -> (factor.label == "SMS") }).findFirst()
        assertThat("No SMS factor found", factor.isPresent())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/enroll-sms-response", 200, MediaType.APPLICATION_JSON)
        authenticationResponse = idxAuthenticationWrapper.selectFactor(
                authenticationResponse.proceedContext, factor.get()
        )
        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(authenticationResponse.getAuthenticationStatus(),
                equalTo(AuthenticationStatus.AWAITING_CHANNEL_DATA_ENROLLMENT))

        setMockResponse(requestExecutor, "challenge/send", scenario + "/challenge-response", 200, MediaType.APPLICATION_JSON)
        VerifyChannelDataOptions verifyChannelDataOptions = new VerifyChannelDataOptions("phoneNumber", "+11234567890")
        authenticationResponse = idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.proceedContext, verifyChannelDataOptions)

        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(authenticationResponse.getAuthenticationStatus(),
                equalTo(AuthenticationStatus.AWAITING_POLL_ENROLLMENT))

        setMockResponse(requestExecutor, "challenge/poll", scenario + "/poll-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "token", scenario + "/token-response", 200, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.poll(authenticationResponse.proceedContext)

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    @Test
    void enrollWithOktaVerifyEmailTest() {

        def scenario = "scenario_10_3_3"
        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "enroll", "enroll-user-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse beginResponse = idxAuthenticationWrapper.begin()
        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues(beginResponse.proceedContext)
        assertThat(newUserRegistrationResponse.getErrors(), empty())
        assertThat(newUserRegistrationResponse.getFormValues(), notNullValue())

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)

        IDXClientContext idxClientContext = newUserRegistrationResponse.getProceedContext().getClientContext()

        assertThat(idxClientContext.state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(idxClientContext.codeVerifier,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().codeVerifier))

        setMockResponse(requestExecutor, "introspect", "enroll-user-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "enroll/new", "enroll-profile-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper
                .register(newUserRegistrationResponse.getProceedContext(), getUserProfile(), null)

        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))

        Authenticator passwordAuthenticator = new Authenticator(
                authenticationResponse.authenticators.first().id,
                authenticationResponse.authenticators.first().type,
                authenticationResponse.authenticators.first().label,
                authenticationResponse.authenticators.first().factors,
                authenticationResponse.authenticators.first().hasNestedFactors())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/credential-enroll-password-response", 200, MediaType.APPLICATION_JSON)
        authenticationResponse = idxAuthenticationWrapper
                .selectAuthenticator(authenticationResponse.getProceedContext(), passwordAuthenticator)

        setMockResponse(requestExecutor, "challenge/answer", scenario + "/challenge-answer-password-response", 200, mediaTypeAppIonJson)
        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("Abcd1234")
        authenticationResponse = idxAuthenticationWrapper
                .verifyAuthenticator(authenticationResponse.getProceedContext(), verifyAuthenticatorOptions)

        Optional<Authenticator> authenticator = authenticationResponse.getAuthenticators()
                .stream().filter({ auth -> (auth.label == "Okta Verify") }).findFirst()
        assertThat("No Okta Verify authenticator found", authenticator.isPresent())

        Optional<Authenticator.Factor> factor = authenticator.get().getFactors()
                .stream().filter({ factor -> (factor.label == "EMAIL") }).findFirst()
        assertThat("No EMAIL factor found", factor.isPresent())

        setMockResponse(requestExecutor, "credential/enroll", scenario + "/enroll-email-response", 200, MediaType.APPLICATION_JSON)
        authenticationResponse = idxAuthenticationWrapper.selectFactor(
                authenticationResponse.proceedContext, factor.get()
        )
        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(authenticationResponse.getAuthenticationStatus(),
                equalTo(AuthenticationStatus.AWAITING_CHANNEL_DATA_ENROLLMENT))

        setMockResponse(requestExecutor, "challenge/send", scenario + "/challenge-response", 200, MediaType.APPLICATION_JSON)
        VerifyChannelDataOptions verifyChannelDataOptions = new VerifyChannelDataOptions("email", "some.user@example.com")
        authenticationResponse = idxAuthenticationWrapper.verifyAuthenticator(authenticationResponse.proceedContext, verifyChannelDataOptions)

        assertThat(authenticationResponse.getProceedContext().getClientContext(), notNullValue())
        assertThat(authenticationResponse.getProceedContext().getClientContext().state,
                equalTo(newUserRegistrationResponse.getProceedContext().getClientContext().state))
        assertThat(authenticationResponse.getAuthenticationStatus(),
                equalTo(AuthenticationStatus.AWAITING_POLL_ENROLLMENT))

        setMockResponse(requestExecutor, "challenge/poll", scenario + "/poll-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "token", scenario + "/token-response", 200, mediaTypeAppIonJson)
        authenticationResponse = idxAuthenticationWrapper.poll(authenticationResponse.proceedContext)

        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getErrors(), empty())
        assertThat(authenticationResponse.getAuthenticationStatus(), is(AuthenticationStatus.SUCCESS))
        assertThat(authenticationResponse.getAuthenticators(), nullValue())
    }

    void setMockResponse(RequestExecutor requestExecutor, String resourceUrlEndsWith,
                         String responseName, Integer httpStatus, MediaType mediaType) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null &&
                            (request as Request).getResourceUrl().getPath().endsWith(resourceUrlEndsWith)
                }) as Request)
        ).thenReturn(getResponseByResourceFileName(responseName, httpStatus, mediaType))
    }

    void setMockResponseOnlyIfBodyParamMatches(RequestExecutor requestExecutor, String resourceUrlEndsWith, String bodyParamName,
                                               String responseName, Integer httpStatus, MediaType mediaType) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null &&
                            (request as Request).getResourceUrl().getPath().endsWith(resourceUrlEndsWith) && request.body.getText().contains(bodyParamName)
                }) as Request)
        ).thenReturn(getResponseByResourceFileName(responseName, httpStatus, mediaType))
    }

    void setMockResponseOnlyIfBodyParamWontMatch(RequestExecutor requestExecutor, String resourceUrlEndsWith, String bodyParamName,
                                                 String responseName, Integer httpStatus, MediaType mediaType) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null &&
                            (request as Request).getResourceUrl().getPath().endsWith(resourceUrlEndsWith) && !request.body.getText().contains(bodyParamName)
                }) as Request)
        ).thenReturn(getResponseByResourceFileName(responseName, httpStatus, mediaType))
    }

    Response getResponseByResourceFileName(String responseName, Integer httpStatus, MediaType mediaType) {
        if (mediaType == mediaTypeTextHtml) {
            return new DefaultResponse(
                    httpStatus,
                    mediaType,
                    new FileInputStream(getClass().getClassLoader().getResource(responseName + ".html").getFile()),
                    -1)
        }
        // default
        return new DefaultResponse(
                httpStatus,
                mediaType,
                new FileInputStream(getClass().getClassLoader().getResource(responseName + ".json").getFile()),
                -1)
    }

    static UserProfile getUserProfile() {
        UserProfile userProfile = new UserProfile()
        userProfile.addAttribute("lastName", "Last")
        userProfile.addAttribute("firstName", "First")
        userProfile.addAttribute("email", "email@test.com")
        return userProfile
    }

    static ClientConfiguration getClientConfiguration() {
        ClientConfiguration clientConfiguration = new ClientConfiguration()
        clientConfiguration.setIssuer("https://example.com")
        clientConfiguration.setClientId("test-client-id")
        clientConfiguration.setClientSecret("test-client-secret")
        clientConfiguration.setScopes(["test-scope"] as Set)
        clientConfiguration.setRedirectUri("https://example.com/login/callback")
        return clientConfiguration
    }

    static void setInternalState(Object target, String fieldName, Object value) {
        Class<?> clazz = target.getClass()
        try {
            Field field = clazz.getDeclaredField(fieldName)
            field.setAccessible(true)
            field.set(target, value)
        } catch (SecurityException | NoSuchFieldException | IllegalArgumentException | IllegalAccessException e) {
            throw new RuntimeException("Unable to set internal state on a private field. [...]", e)
        }
    }

    static Object getInternalState(Object target, String fieldName) {
        Class<?> clazz = target.getClass()
        try {
            Field field = clazz.getDeclaredField(fieldName)
            field.setAccessible(true)
            return field.get(target)
        } catch (SecurityException | NoSuchFieldException | IllegalArgumentException | IllegalAccessException e) {
            throw new RuntimeException("Unable to get internal state on a private field. [...]", e)
        }
    }
}
