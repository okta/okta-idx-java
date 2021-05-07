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
import com.okta.idx.sdk.api.model.AuthenticationStatus
import com.okta.idx.sdk.api.model.AuthenticatorUIOptions
import com.okta.idx.sdk.api.model.IDXClientContext
import com.okta.idx.sdk.api.model.UserProfile
import com.okta.idx.sdk.api.model.VerifyAuthenticatorOptions
import com.okta.idx.sdk.api.response.AuthenticationResponse
import com.okta.idx.sdk.api.response.NewUserRegistrationResponse
import com.okta.idx.sdk.api.util.ClassUtil
import org.testng.annotations.Test

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*
import static org.mockito.ArgumentMatchers.argThat
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

class AuthenticationWrapperTest {

    final MediaType mediaTypeAppIonJson = MediaType.valueOf("application/ion+json; okta-version=1.0.0")

    @Test
    void registerTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setStubbedInteractResponse(requestExecutor)
        setStubbedIntrospectResponse(requestExecutor)
        setStubbedEnrollProfileResponse(requestExecutor)

        NewUserRegistrationResponse newUserRegistrationResponse = idxAuthenticationWrapper.fetchSignUpFormValues()
        assertThat(newUserRegistrationResponse.getErrors(), nullValue())
        assertThat(newUserRegistrationResponse.getFormValues(), notNullValue())
        assertThat(newUserRegistrationResponse.getFormValues(), hasSize(1))
        assertThat(newUserRegistrationResponse.getIdxClientContext().state, notNullValue())
        assertThat(newUserRegistrationResponse.getIdxClientContext().interactionHandle, notNullValue())
        assertThat(newUserRegistrationResponse.getIdxClientContext().interactionHandle, equalTo("003Q14X7li"))
        assertThat(newUserRegistrationResponse.getIdxClientContext().codeVerifier, notNullValue())
        assertThat(newUserRegistrationResponse.getIdxClientContext().codeChallenge, notNullValue())

        setStubbedInteractResponse(requestExecutor)
        setStubbedIntrospectResponse(requestExecutor)

        IDXClientContext idxClientContext = newUserRegistrationResponse.getIdxClientContext()
        assertThat(idxClientContext.state,
                equalTo(newUserRegistrationResponse.getIdxClientContext().state))
        assertThat(idxClientContext.interactionHandle,
                equalTo(newUserRegistrationResponse.getIdxClientContext().interactionHandle))
        assertThat(idxClientContext.codeVerifier,
                equalTo(newUserRegistrationResponse.getIdxClientContext().codeVerifier))
        assertThat(idxClientContext.codeChallenge,
                equalTo(newUserRegistrationResponse.getIdxClientContext().codeChallenge))

        setStubbedEnrollProfileResponseAfterEnroll(requestExecutor)
        setStubbedEnrollNewResponse(requestExecutor)

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.register(idxClientContext, getUserProfile())
        assertThat(authenticationResponse.getIdxClientContext(), notNullValue())
        assertThat(authenticationResponse.getIdxClientContext().state,
                equalTo(newUserRegistrationResponse.getIdxClientContext().state))
        assertThat(authenticationResponse.getIdxClientContext().interactionHandle,
                equalTo(newUserRegistrationResponse.getIdxClientContext().interactionHandle))
        assertThat(authenticationResponse.getIdxClientContext().codeVerifier,
                equalTo(newUserRegistrationResponse.getIdxClientContext().codeVerifier))
        assertThat(authenticationResponse.getIdxClientContext().codeChallenge,
                equalTo(newUserRegistrationResponse.getIdxClientContext().codeChallenge))

        setStubbedEnrollAuthenticatorResponse(requestExecutor)

        AuthenticatorUIOptions authenticatorUIOptions =
                idxAuthenticationWrapper.populateAuthenticatorUIOptions(idxClientContext)
        assertThat(authenticatorUIOptions.options, notNullValue())
        assertThat(authenticatorUIOptions.options, hasSize(1))
        assertThat(authenticatorUIOptions.options.get(0).type, equalTo("password"))
    }

    @Test
    void verifyEmailErrorResponseTest() {

        def requestExecutor = mock(RequestExecutor)
        def idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)
        def idxAuthenticationWrapper = new IDXAuthenticationWrapper()
        //replace idxClient with mock idxClient
        ClassUtil.setInternalState(idxAuthenticationWrapper, "client", idxClient)

        setStubbedInteractResponse(requestExecutor)
        setStubbedIntrospectResponse(requestExecutor)

        AuthenticationTransaction introspectTransaction = AuthenticationTransaction.create(idxClient);
        VerifyAuthenticatorOptions verifyAuthenticatorOptions = new VerifyAuthenticatorOptions("wrong_code");

        setStubbedChallengeResponse(requestExecutor)
        setStubbedChallengeErrorResponse(requestExecutor)

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.verifyAuthenticator(
                introspectTransaction.getClientContext(),
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

        setStubbedInteractResponse(requestExecutor)
        setStubbedIntrospectResponse(requestExecutor)
        setStubbedRecoverTransactionResponse(requestExecutor)
        setStubbedIdentifyResponse(requestExecutor)

        String userEmail = "joe.coder" + (new Random()).nextInt(1000) + "@example.com"

        AuthenticationResponse authenticationResponse = idxAuthenticationWrapper.recoverPassword(userEmail)
        assertThat(authenticationResponse, notNullValue())
        assertThat(authenticationResponse.getAuthenticationStatus(),
                equalTo(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION))

        setChallengeResponse(requestExecutor)
        setAnswerChallengeResponse(requestExecutor)

        AuthenticatorUIOptions authenticatorUIOptions =
                idxAuthenticationWrapper.populateForgotPasswordAuthenticatorUIOptions(
                        authenticationResponse.getIdxClientContext())
        assertThat(authenticatorUIOptions, notNullValue())
        assertThat(authenticatorUIOptions.options, notNullValue())
        assertThat(authenticatorUIOptions.options, hasSize(1))
        assertThat(authenticatorUIOptions.options.get(0).type, equalTo("email"))
    }

    void setStubbedInteractResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("interact")
                }) as Request)
        ).thenReturn(getResponseByResourceFileName("interact-response", 200, MediaType.APPLICATION_JSON))
    }

    void setStubbedIntrospectResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("introspect")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("introspect-response", 200, mediaTypeAppIonJson))
    }

    void setStubbedEnrollProfileResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("enroll")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("enroll-user-response", 200, mediaTypeAppIonJson))
    }

    void setStubbedEnrollProfileResponseAfterEnroll(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("introspect")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("enroll-user-response", 200, mediaTypeAppIonJson))
    }

    void setStubbedEnrollNewResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("enroll/new")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("enroll-profile-response", 200, mediaTypeAppIonJson))
    }

    void setStubbedEnrollAuthenticatorResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("introspect")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("enroll-registration-response", 200, mediaTypeAppIonJson))
    }

    void setStubbedChallengeResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("introspect")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("challenge-response", 200, mediaTypeAppIonJson))
    }

    void setStubbedChallengeErrorResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("challenge/answer")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("challenge-error-response", 401, mediaTypeAppIonJson))
    }

    void setStubbedRecoverTransactionResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("recover")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("recover-transaction-response", mediaTypeAppIonJson))
    }

    void setStubbedIdentifyResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("identify")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("identify-response", mediaTypeAppIonJson))
    }

    void setChallengeResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("introspect")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("challenge-response", mediaTypeAppIonJson))
    }

    void setAnswerChallengeResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("recover")
                }) as Request
        )).thenReturn(getResponseByResourceFileName("answer-challenge-response", mediaTypeAppIonJson))
    }

    Response getResponseByResourceFileName(String responseName, Integer httpStatus, MediaType mediaType) {
        return new DefaultResponse(
                httpStatus,
                mediaType,
                new FileInputStream(getClass().getClassLoader().getResource(responseName + ".json").getFile()),
                -1)
    }

    UserProfile getUserProfile() {
        UserProfile userProfile = new UserProfile()
        userProfile.addAttribute("lastName", "Last")
        userProfile.addAttribute("firstName", "First")
        userProfile.addAttribute("email", "email@test.com")
    }

    ClientConfiguration getClientConfiguration() {
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
