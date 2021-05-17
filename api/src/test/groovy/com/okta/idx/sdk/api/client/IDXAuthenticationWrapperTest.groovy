/*
 * Copyright 2021-Present Okta, Inc.
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
import com.okta.idx.sdk.api.model.IDXClientContext
import com.okta.idx.sdk.api.model.UserProfile
import com.okta.idx.sdk.api.model.VerifyAuthenticatorOptions
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

    @Test
    void registerTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "enroll", "enroll-user-response", 200, mediaTypeAppIonJson)

        AuthenticationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues()
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
                idxAuthenticationWrapper.register(newUserRegistrationResponse.getProceedContext(), getUserProfile())
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
                        introspectTransaction.getStateHandle(), "/challenge/answer", null),
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

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.recoverPassword(userEmail)
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

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password")
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

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password")
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

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password")
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
    void authenticateIdentifyFirstFailTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setMockResponse(requestExecutor, "interact", "interact-response", 200, MediaType.APPLICATION_JSON)
        setMockResponse(requestExecutor, "introspect", "introspect-identify-first-response", 200, mediaTypeAppIonJson)
        setMockResponse(requestExecutor, "identify", "identify-first-error-response", 400, mediaTypeAppIonJson)

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password")
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

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password")
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

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.authenticate(
                new AuthenticationOptions("username", "password")
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

    void setMockResponse(RequestExecutor requestExecutor,
                         String resourceUrlEndsWith, String responseName, Integer httpStatus, MediaType mediaType ) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && (request as Request).getResourceUrl().getPath().endsWith(resourceUrlEndsWith)
                }) as Request)
        ).thenReturn(getResponseByResourceFileName(responseName, httpStatus, mediaType))
    }

    Response getResponseByResourceFileName(String responseName, Integer httpStatus, MediaType mediaType) {
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
        return userProfile;
    }

    static ClientConfiguration getClientConfiguration() {
        ClientConfiguration clientConfiguration = new ClientConfiguration()
        clientConfiguration.setIssuer("http://example.com")
        clientConfiguration.setClientId("test-client-id")
        clientConfiguration.setClientSecret("test-client-secret")
        clientConfiguration.setScopes(["test-scope"] as Set)
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
}
