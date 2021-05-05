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
import com.okta.idx.sdk.api.model.AuthenticatorUIOptions
import com.okta.idx.sdk.api.model.IDXClientContext
import com.okta.idx.sdk.api.model.UserProfile
import com.okta.idx.sdk.api.response.AuthenticationResponse
import com.okta.idx.sdk.api.response.NewUserRegistrationResponse
import org.testng.annotations.Ignore
import org.testng.annotations.Test

import java.lang.reflect.Field

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.*
import static org.mockito.ArgumentMatchers.argThat
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

class AuthenticationWrapperTest {

    @Ignore
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
        assertThat(authenticatorUIOptions.options.get(0).type, equalTo("security_question"))
    }

    void setStubbedInteractResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("interact")
                }) as Request)
        ).thenReturn(getStubbedInteractResponse())
    }

    void setStubbedIntrospectResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("introspect")
                }) as Request
        )).thenReturn(getStubbedIntrospectResponse())
    }

    void setStubbedEnrollProfileResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("enroll")
                }) as Request
        )).thenReturn(getStubbedEnrollProfileResponse())
    }

    void setStubbedEnrollProfileResponseAfterEnroll(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("introspect")
                }) as Request
        )).thenReturn(getStubbedEnrollProfileResponse())
    }

    void setStubbedEnrollNewResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("enroll/new")
                }) as Request
        )).thenReturn(getStubbedEnrollNewResponse())
    }

    void setStubbedEnrollAuthenticatorResponse(RequestExecutor requestExecutor) {
        when(requestExecutor.executeRequest(
                argThat({
                    request -> request != null && ((Request) request).getResourceUrl().toString().endsWith("introspect")
                }) as Request
        )).thenReturn(getStubbedEnrollAuthenticatorResponse())
    }

    Response getStubbedInteractResponse() {
        return new DefaultResponse(
                200,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("interact-response.json").getFile()),
                -1)
    }

    Response getStubbedIntrospectResponse() {
        return new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("introspect-response.json").getFile()),
                -1)
    }

    Response getStubbedEnrollProfileResponse() {
        return new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("enroll-user-response.json").getFile()),
                -1)
    }

    Response getStubbedEnrollNewResponse() {
        return new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("enroll-profile-response.json").getFile()),
                -1)
    }

    Response getStubbedEnrollAuthenticatorResponse() {
        return new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("enroll-response.json").getFile()),
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
