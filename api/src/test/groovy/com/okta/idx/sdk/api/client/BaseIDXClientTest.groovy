/*
 * Copyright (c) 2020-Present, Okta, Inc.
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

import com.okta.commons.http.DefaultResponse
import com.okta.commons.http.HttpException
import com.okta.commons.http.HttpHeaders
import com.okta.commons.http.MediaType
import com.okta.commons.http.Request
import com.okta.commons.http.RequestExecutor
import com.okta.commons.http.Response
import com.okta.idx.sdk.api.exception.ProcessingException
import com.okta.idx.sdk.api.model.Authenticator
import com.okta.idx.sdk.api.model.AuthenticatorEnrollment
import com.okta.idx.sdk.api.model.Credentials
import com.okta.idx.sdk.api.model.EmailTokenType
import com.okta.idx.sdk.api.model.FormValue
import com.okta.idx.sdk.api.model.IDXClientContext
import com.okta.idx.sdk.api.model.Options
import com.okta.idx.sdk.api.model.RemediationOption
import com.okta.idx.sdk.api.model.RequestContext
import com.okta.idx.sdk.api.model.UserProfile
import com.okta.idx.sdk.api.request.AnswerChallengeRequest
import com.okta.idx.sdk.api.request.AnswerChallengeRequestBuilder
import com.okta.idx.sdk.api.request.ChallengeRequest
import com.okta.idx.sdk.api.request.ChallengeRequestBuilder
import com.okta.idx.sdk.api.request.EnrollRequest
import com.okta.idx.sdk.api.request.EnrollRequestBuilder
import com.okta.idx.sdk.api.request.EnrollUserProfileUpdateRequest
import com.okta.idx.sdk.api.request.EnrollUserProfileUpdateRequestBuilder
import com.okta.idx.sdk.api.request.IdentifyRequest
import com.okta.idx.sdk.api.request.IdentifyRequestBuilder
import com.okta.idx.sdk.api.request.RecoverRequest
import com.okta.idx.sdk.api.request.RecoverRequestBuilder
import com.okta.idx.sdk.api.request.SkipAuthenticatorEnrollmentRequest
import com.okta.idx.sdk.api.request.SkipAuthenticatorEnrollmentRequestBuilder

import com.okta.idx.sdk.api.response.IDXResponse
import com.okta.idx.sdk.api.response.TokenResponse
import com.okta.idx.sdk.api.config.ClientConfiguration
import org.hamcrest.CoreMatchers
import org.mockito.ArgumentCaptor
import org.testng.annotations.Test

import java.util.stream.Collectors

import static com.okta.idx.sdk.api.util.ClientUtil.normalizedIssuerUri

import static org.hamcrest.Matchers.arrayWithSize
import static org.hamcrest.Matchers.hasSize
import static org.hamcrest.Matchers.is
import static org.mockito.Mockito.any
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.times
import static org.mockito.Mockito.verify
import static org.mockito.Mockito.when

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.hasItemInArray
import static org.hamcrest.Matchers.notNullValue
import static org.hamcrest.Matchers.nullValue

class BaseIDXClientTest {

    @Test
    void testIDXClientContext() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("interact-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedResponse)
        ArgumentCaptor<Request> argumentCaptor = ArgumentCaptor.forClass(Request.class)

        IDXClientContext idxClientContext = idxClient.interact()

        verify(requestExecutor, times(1)).executeRequest(argumentCaptor.capture())

        def httpHeaders = argumentCaptor.getValue().getHeaders()

        assertThat(httpHeaders.size(), is(4))
        assertThat(httpHeaders.getFirst("Content-Type"), is("application/x-www-form-urlencoded"))
        assertThat(httpHeaders.getFirst("Accept"), is("application/json"))
        assertThat(httpHeaders.getFirst(HttpHeaders.USER_AGENT), notNullValue())
        assertThat(httpHeaders.getFirst("Connection"), is("close"))

        assertThat(idxClientContext, notNullValue())
        assertThat(idxClientContext.getCodeVerifier(), notNullValue())
        assertThat(idxClientContext.getState(), notNullValue())
        assertThat(idxClientContext.getInteractionHandle(), is("003Q14X7li"))
    }

    @Test
    void testInteractWithRequestContext_ConfidentialClient() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("interact-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedResponse)
        ArgumentCaptor<Request> argumentCaptor = ArgumentCaptor.forClass(Request.class)

        final RequestContext requestContext = new RequestContext()
        requestContext.setDeviceToken("test_x_device_token")
        requestContext.setUserAgent("test_x_okta_user_agent_extended")
        requestContext.setIpAddress("test_x_forwarded_for")

        final IDXClientContext idxClientContext = idxClient.interact(null, null, requestContext)

        verify(requestExecutor, times(1)).executeRequest(argumentCaptor.capture())

        def httpHeaders = argumentCaptor.getValue().getHeaders()
        assertThat(httpHeaders.size(), is(7))
        assertThat(httpHeaders.getFirst("Content-Type"), is("application/x-www-form-urlencoded"))
        assertThat(httpHeaders.getFirst("Accept"), is("application/json"))
        assertThat(httpHeaders.getFirst(HttpHeaders.USER_AGENT), notNullValue())

        // assert request context headers
        assertThat(httpHeaders.getFirst(RequestContext.X_DEVICE_TOKEN), is("test_x_device_token"))
        assertThat(httpHeaders.getFirst(RequestContext.X_FORWARDED_FOR), is("test_x_forwarded_for"))
        assertThat(httpHeaders.getFirst(RequestContext.X_OKTA_USER_AGENT_EXTENDED), is("test_x_okta_user_agent_extended"))

        assertThat(idxClientContext, notNullValue())
        assertThat(idxClientContext.getCodeVerifier(), notNullValue())
        assertThat(idxClientContext.getState(), notNullValue())
        assertThat(idxClientContext.getInteractionHandle(), is("003Q14X7li"))
    }

    @Test
    void testInteractWithRequestContext_NonConfidentialClient() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final ClientConfiguration clientConfiguration = getClientConfiguration()
        // non-confidential client
        clientConfiguration.setClientSecret(null)

        final IDXClient idxClient = new BaseIDXClient(clientConfiguration, requestExecutor)

        final Response stubbedResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("interact-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedResponse)
        ArgumentCaptor<Request> argumentCaptor = ArgumentCaptor.forClass(Request.class)

        final RequestContext requestContext = new RequestContext()
        requestContext.setDeviceToken("test_x_device_token")
        requestContext.setUserAgent("test_x_okta_user_agent_extended")
        requestContext.setIpAddress("test_x_forwarded_for")

        final IDXClientContext idxClientContext = idxClient.interact(null, null, requestContext)

        verify(requestExecutor, times(1)).executeRequest(argumentCaptor.capture())

        def httpHeaders = argumentCaptor.getValue().getHeaders()
        assertThat(httpHeaders.size(), is(5))
        assertThat(httpHeaders.getFirst("Content-Type"), is("application/x-www-form-urlencoded"))
        assertThat(httpHeaders.getFirst("Accept"), is("application/json"))
        assertThat(httpHeaders.getFirst(HttpHeaders.USER_AGENT), notNullValue())

        // assert request context headers
        // 'X-Device-Token' & 'X-Forwarded-For' headers will not be set for non-confidential clients
        assertThat(httpHeaders.getFirst(RequestContext.X_DEVICE_TOKEN), nullValue())
        assertThat(httpHeaders.getFirst(RequestContext.X_FORWARDED_FOR), nullValue())

        assertThat(httpHeaders.getFirst(RequestContext.X_OKTA_USER_AGENT_EXTENDED), is("test_x_okta_user_agent_extended"))

        assertThat(idxClientContext, notNullValue())
        assertThat(idxClientContext.getCodeVerifier(), notNullValue())
        assertThat(idxClientContext.getState(), notNullValue())
        assertThat(idxClientContext.getInteractionHandle(), is("003Q14X7li"))
    }

    @Test
    void testInteractWithRecoveryToken() {
        RequestExecutor requestExecutor = mock(RequestExecutor)
        final Response stubbedResponse = new DefaultResponse(
                200,
                MediaType.APPLICATION_JSON,
                new FileInputStream(getClass().getClassLoader().getResource("interact-response.json").getFile()),
                -1)
        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedResponse)
        ArgumentCaptor<Request> argumentCaptor = ArgumentCaptor.forClass(Request.class)
        final IDXClient idxClient = new BaseIDXClient(getClientConfiguration(), requestExecutor)

        IDXClientContext idxClientContext = idxClient.interact("sample-token_123", EmailTokenType.RECOVERY_TOKEN, null)

        verify(requestExecutor, times(1)).executeRequest(argumentCaptor.capture())
        InputStream body = argumentCaptor.getValue().getBody()
        String parameters = new BufferedReader(new InputStreamReader(body)).lines().collect(Collectors.joining())

        assertThat(idxClientContext, notNullValue())
        assertThat(idxClientContext.getCodeVerifier(), notNullValue())
        assertThat(idxClientContext.getState(), notNullValue())
        assertThat(idxClientContext.getInteractionHandle(), is("003Q14X7li"))
        assertThat(parameters, CoreMatchers.containsString("&recovery_token=sample-token_123"))
    }

    @Test
    void testIntrospectResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedInteractResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("interact-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedInteractResponse)

        IDXClientContext idxClientContext = idxClient.interact()

        final Response stubbedIntrospectResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("introspect-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedIntrospectResponse)

        IDXResponse response = idxClient.introspect(idxClientContext)

        assertThat(response, notNullValue())
        assertThat(response.remediation(), notNullValue())
        assertThat(response.getMessages(), nullValue())
        assertThat(response.remediation().remediationOptions(), notNullValue())

        assertThat(response.expiresAt, equalTo("2020-10-31T01:42:02.000Z"))
        assertThat(response.intent, equalTo("LOGIN"))
        assertThat(response.remediation.type, equalTo("array"))
        assertThat(response.remediation.value.first().rel, hasItemInArray("create-form"))
        assertThat(response.remediation.value.first().name, equalTo("identify"))
        assertThat(response.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/identify"))
        assertThat(response.remediation.value.first().method, equalTo("POST"))
        assertThat(response.remediation.value.first().accepts, equalTo("application/ion+json; okta-version=1.0.0"))

        assertThat(response.remediation().remediationOptions().first().form(), notNullValue())

        FormValue[] formValues = response.remediation().remediationOptions().first().form()

        Optional<FormValue> stateHandleForm = Arrays.stream(formValues)
                .filter({ x -> ("stateHandle" == x.getName()) })
                .findFirst()

        FormValue stateHandleFormValue = stateHandleForm.get()

        assertThat(stateHandleFormValue, notNullValue())
        assertThat(stateHandleFormValue.required, equalTo(true))
        assertThat(stateHandleFormValue.value, equalTo("02tYS1NHhCPLcOpT3GByBBRHmGU63p7LGRXJx5cOvp"))
        assertThat(stateHandleFormValue.visible, equalTo(false))
        assertThat(stateHandleFormValue.mutable, equalTo(false))

        Optional<FormValue> identifierForm = Arrays.stream(formValues)
                .filter({ x -> ("identifier" == x.getName()) })
                .findFirst()

        FormValue identifierFormValue = identifierForm.get()

        assertThat(identifierFormValue, notNullValue())
        assertThat(identifierFormValue.label, equalTo("Username"))

        Optional<FormValue> rememberMeForm = Arrays.stream(formValues)
                .filter({ x -> ("rememberMe" == x.getName()) })
                .findFirst()

        FormValue rememberMeFormValue = rememberMeForm.get()

        assertThat(rememberMeFormValue, notNullValue())
        assertThat(rememberMeFormValue.label, equalTo("Remember this device"))
        assertThat(rememberMeFormValue.type, equalTo("boolean"))
    }

    @Test
    void testIdentifyResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedInteractResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("interact-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedInteractResponse)

        IDXClientContext idxClientContext = idxClient.interact()

        final Response stubbedIntrospectResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("introspect-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedIntrospectResponse)

        IDXResponse introspectResponse = idxClient.introspect(idxClientContext)

        assertThat(introspectResponse.remediation().remediationOptions(), notNullValue())
        assertThat(introspectResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/identify"))

        IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
                .withIdentifier("test-identifier")
                .withStateHandle("stateHandle")
                .build()

        final Response stubbedIdentifyResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("identify-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedIdentifyResponse)

        IDXResponse identifyResponse =
                introspectResponse.remediation().remediationOptions().first().proceed(idxClient, identifyRequest)

        assertThat(identifyResponse, notNullValue())
        assertThat(identifyResponse.stateHandle, notNullValue())
        assertThat(identifyResponse.version, notNullValue())
        assertThat(identifyResponse.expiresAt, equalTo("2020-10-30T23:47:46.000Z"))
        assertThat(identifyResponse.intent, equalTo("LOGIN"))
        assertThat(identifyResponse.remediation.type, equalTo("array"))

        // authenticatorEnrollments
        assertThat(identifyResponse.authenticatorEnrollments, notNullValue())

        AuthenticatorEnrollment emailAuthEnrollment = identifyResponse.authenticatorEnrollments.values.find {it.type == "email"}
        assertThat(emailAuthEnrollment, notNullValue())
        assertThat(emailAuthEnrollment.profile, notNullValue())
        assertThat(emailAuthEnrollment.id, equalTo("eae3iyi3yzHZN4Cji1d6"))
        assertThat(emailAuthEnrollment.type, equalTo("email"))
        assertThat(emailAuthEnrollment.displayName, equalTo("Email"))
        assertThat(emailAuthEnrollment.profile.email, notNullValue())
        assertThat(emailAuthEnrollment.methods, notNullValue())
        assertThat(emailAuthEnrollment.methods.first(), notNullValue())
        assertThat(emailAuthEnrollment.methods.first().type, equalTo("email"))

        AuthenticatorEnrollment passwordAuthEnrollment = identifyResponse.authenticatorEnrollments.values.find {it.type == "password"}
        assertThat(passwordAuthEnrollment, notNullValue())
        assertThat(passwordAuthEnrollment.profile, nullValue())
        assertThat(passwordAuthEnrollment.id, equalTo("laekusi77LNcWg2rX1d5"))
        assertThat(passwordAuthEnrollment.type, equalTo("password"))
        assertThat(passwordAuthEnrollment.displayName, equalTo("Password"))
        assertThat(passwordAuthEnrollment.methods, notNullValue())
        assertThat(passwordAuthEnrollment.methods.first(), notNullValue())
        assertThat(passwordAuthEnrollment.methods.first().type, equalTo("password"))

        AuthenticatorEnrollment secQnAuthEnrollment = identifyResponse.authenticatorEnrollments.values.find {it.type == "security_question"}
        assertThat(secQnAuthEnrollment, notNullValue())
        assertThat(secQnAuthEnrollment.profile, notNullValue())
        assertThat(secQnAuthEnrollment.id, equalTo("qae3iypdrSLDqUoY81d6"))
        assertThat(secQnAuthEnrollment.type, equalTo("security_question"))
        assertThat(secQnAuthEnrollment.displayName, equalTo("Security Question"))
        assertThat(secQnAuthEnrollment.methods, notNullValue())
        assertThat(secQnAuthEnrollment.methods.first(), notNullValue())
        assertThat(secQnAuthEnrollment.methods.first().type, equalTo("security_question"))

        assertThat(identifyResponse.remediation.value.first().form(), notNullValue())

        FormValue[] formValues = identifyResponse.remediation().remediationOptions().first().form()

        Optional<FormValue> stateHandleForm = Arrays.stream(formValues)
                .filter({ x -> ("stateHandle" == x.getName()) })
                .findFirst()

        FormValue stateHandleFormValue = stateHandleForm.get()

        assertThat(stateHandleFormValue, notNullValue())
        assertThat(stateHandleFormValue.required, equalTo(true))
        assertThat(stateHandleFormValue.value, equalTo("02tYS1NHhCPLcOpT3GByBBRHmGU63p7LGRXJx5cOvp"))
        assertThat(stateHandleFormValue.visible, equalTo(false))
        assertThat(stateHandleFormValue.mutable, equalTo(false))

        Optional<FormValue> authenticatorForm = Arrays.stream(formValues)
                .filter({ x -> ("authenticator" == x.getName()) })
                .findFirst()

        FormValue authenticatorFormValue = authenticatorForm.get()

        assertThat(authenticatorFormValue, notNullValue())
        assertThat(authenticatorFormValue.type, equalTo("object"))

        // Email
        Options emailOption = authenticatorFormValue.options().find {it.label == "Email"}

        FormValue idForm = emailOption.getValue().getForm().getValue().find {it.name == "id"}
        assertThat(idForm, notNullValue())
        assertThat(idForm.required, equalTo(true))
        assertThat(idForm.value, equalTo("aut2ihzk1gHl7ynhd1d6"))
        assertThat(idForm.mutable, equalTo(false))

        FormValue methodTypeForm = emailOption.getValue().getForm().getValue().find {it.name == "methodType"}
        assertThat(methodTypeForm, notNullValue())
        assertThat(methodTypeForm.required, equalTo(false))
        assertThat(methodTypeForm.value, equalTo("email"))
        assertThat(methodTypeForm.mutable, equalTo(false))

        // Password
        Options passwordOption = authenticatorFormValue.options().find {it.label == "Password"}

        idForm = passwordOption.getValue().getForm().getValue().find {it.name == "id"}
        assertThat(idForm, notNullValue())
        assertThat(idForm.required, equalTo(true))
        assertThat(idForm.value, equalTo("aut2ihzk2n15tsQnQ1d6"))
        assertThat(idForm.mutable, equalTo(false))

        methodTypeForm = passwordOption.getValue().getForm().getValue().find {it.name == "methodType"}
        assertThat(methodTypeForm, notNullValue())
        assertThat(methodTypeForm.required, equalTo(false))
        assertThat(methodTypeForm.value, equalTo("password"))
        assertThat(methodTypeForm.mutable, equalTo(false))

        // Security Question
        Options secQnOption = authenticatorFormValue.options().find {it.label == "Security Question"}

        idForm = secQnOption.getValue().getForm().getValue().find {it.name == "id"}
        assertThat(idForm, notNullValue())
        assertThat(idForm.required, equalTo(true))
        assertThat(idForm.value, equalTo("aut2ihzk4hgf9sIQa1d6"))
        assertThat(idForm.mutable, equalTo(false))

        methodTypeForm = secQnOption.getValue().getForm().getValue().find {it.name == "methodType"}
        assertThat(methodTypeForm, notNullValue())
        assertThat(methodTypeForm.required, equalTo(false))
        assertThat(methodTypeForm.value, equalTo("security_question"))
        assertThat(methodTypeForm.mutable, equalTo(false))
    }

    @Test
    void testChallengeResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedInteractResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("interact-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedInteractResponse)

        IDXClientContext idxClientContext = idxClient.interact()

        final Response stubbedIntrospectResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("introspect-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedIntrospectResponse)

        IDXResponse introspectResponse = idxClient.introspect(idxClientContext)

        assertThat(introspectResponse.remediation().remediationOptions(), notNullValue())
        assertThat(introspectResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/identify"))

        IdentifyRequest identifyRequest = new IdentifyRequest("test-identifier", null, false, "stateHandle")

        final Response stubbedIdentifyResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("identify-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedIdentifyResponse)

        IDXResponse identifyResponse =
                introspectResponse.remediation().remediationOptions().first().proceed(idxClient, identifyRequest)

        assertThat(identifyResponse, notNullValue())
        assertThat(identifyResponse.stateHandle, notNullValue())
        assertThat(identifyResponse.version, notNullValue())
        assertThat(identifyResponse.expiresAt, equalTo("2020-10-30T23:47:46.000Z"))
        assertThat(identifyResponse.intent, equalTo("LOGIN"))
        assertThat(identifyResponse.remediation.type, equalTo("array"))

        assertThat(identifyResponse.remediation().remediationOptions(), notNullValue())
        assertThat(identifyResponse.remediation.value.first().rel, hasItemInArray("create-form"))
        assertThat(identifyResponse.remediation.value.first().name, equalTo("select-authenticator-authenticate"))
        assertThat(identifyResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/challenge"))
        assertThat(identifyResponse.remediation.value.first().method, equalTo("POST"))
        assertThat(identifyResponse.remediation.value.first().accepts, equalTo("application/ion+json; okta-version=1.0.0"))

        assertThat(identifyResponse.remediation.value.first().form(), notNullValue())

        // proceed with password authenticator challenge
        Authenticator passwordAuthenticator = new Authenticator()
        passwordAuthenticator.setId("")
        passwordAuthenticator.setMethodType("password")

        ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                .withStateHandle("stateHandle")
                .withAuthenticator(passwordAuthenticator)
                .build()

        final Response stubbedChallengeResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("challenge-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedChallengeResponse)

        IDXResponse passwordAuthenticatorChallengeResponse =
                identifyResponse.remediation().remediationOptions().first().proceed(idxClient, passwordAuthenticatorChallengeRequest)

        assertThat(passwordAuthenticatorChallengeResponse.stateHandle, notNullValue())
        assertThat(passwordAuthenticatorChallengeResponse.version, notNullValue())
        assertThat(passwordAuthenticatorChallengeResponse.expiresAt, equalTo("2020-10-29T21:17:28.000Z"))
        assertThat(passwordAuthenticatorChallengeResponse.intent, equalTo("LOGIN"))
        assertThat(passwordAuthenticatorChallengeResponse.remediation.type, equalTo("array"))

        assertThat(passwordAuthenticatorChallengeResponse.remediation().remediationOptions(), notNullValue())
        assertThat(passwordAuthenticatorChallengeResponse.remediation.value.first().rel, hasItemInArray("create-form"))
        assertThat(passwordAuthenticatorChallengeResponse.remediation.value.first().name, equalTo("challenge-authenticator"))
        assertThat(passwordAuthenticatorChallengeResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/challenge/answer"))
        assertThat(passwordAuthenticatorChallengeResponse.remediation.value.first().method, equalTo("POST"))
        assertThat(passwordAuthenticatorChallengeResponse.remediation.value.first().accepts, equalTo("application/ion+json; okta-version=1.0.0"))

        assertThat(passwordAuthenticatorChallengeResponse.remediation.value.first().form(), notNullValue())

        FormValue[] formValues = passwordAuthenticatorChallengeResponse.remediation().remediationOptions().first().form()

        Optional<FormValue> stateHandleForm = Arrays.stream(formValues)
                .filter({ x -> ("stateHandle" == x.getName()) })
                .findFirst()

        FormValue stateHandleFormValue = stateHandleForm.get()

        assertThat(stateHandleFormValue, notNullValue())
        assertThat(stateHandleFormValue.required, equalTo(true))
        assertThat(stateHandleFormValue.value, equalTo("025r9Yn758Z-zwhMGDm1saTaW1pVRy4t9oTxM7dLYE"))
        assertThat(stateHandleFormValue.visible, equalTo(false))
        assertThat(stateHandleFormValue.mutable, equalTo(false))

        Optional<FormValue> credentialsFormOptional = Arrays.stream(formValues)
                .filter({ x -> ("credentials" == x.getName()) })
                .findFirst()

        FormValue credentialsForm = credentialsFormOptional.get()

        assertThat(credentialsForm, notNullValue())
        assertThat(credentialsForm.required, equalTo(true))
        assertThat(credentialsForm.form(), notNullValue())
        assertThat(credentialsForm.form().getValue(), notNullValue())

        FormValue credentialsFormValue = credentialsForm.form().getValue()
                .find {it.name == "passcode" && it.label == "Password" && it.secret }

        assertThat(credentialsFormValue, notNullValue())

        // other authenticators
        RemediationOption authenticatorOption = passwordAuthenticatorChallengeResponse.remediation().remediationOptions()
                .find {it.name == "select-authenticator-authenticate"}

        assertThat(authenticatorOption, notNullValue())
        assertThat(authenticatorOption.rel, hasItemInArray("create-form"))
        assertThat(authenticatorOption.href, equalTo("https://foo.oktapreview.com/idp/idx/challenge"))
        assertThat(authenticatorOption.method, equalTo("POST"))
        assertThat(authenticatorOption.form(), notNullValue())

        FormValue authenticatorOptions = authenticatorOption.form().find {it.name == "authenticator"}
        assertThat(authenticatorOptions, notNullValue())
        assertThat(authenticatorOptions.type, equalTo("object"))

        // Email
        Options emailOption = authenticatorOptions.options().find {it.label == "Email"}

        FormValue idForm = emailOption.getValue().getForm().getValue().find {it.name == "id"}
        assertThat(idForm, notNullValue())
        assertThat(idForm.required, equalTo(true))
        assertThat(idForm.value, equalTo("aut2ihzk1gHl7ynhd1d6"))
        assertThat(idForm.mutable, equalTo(false))

        FormValue methodTypeForm = emailOption.getValue().getForm().getValue().find {it.name == "methodType"}
        assertThat(methodTypeForm, notNullValue())
        assertThat(methodTypeForm.required, equalTo(false))
        assertThat(methodTypeForm.value, equalTo("email"))
        assertThat(methodTypeForm.mutable, equalTo(false))

        // Password
        Options passwordOption = authenticatorOptions.options().find {it.label == "Password"}
        assertThat(passwordOption, notNullValue())

        idForm = passwordOption.getValue().getForm().getValue().find {it.name == "id"}
        assertThat(idForm, notNullValue())
        assertThat(idForm.required, equalTo(true))
        assertThat(idForm.value, equalTo("aut2ihzk2n15tsQnQ1d6"))
        assertThat(idForm.mutable, equalTo(false))

        methodTypeForm = passwordOption.getValue().getForm().getValue().find {it.name == "methodType"}
        assertThat(methodTypeForm, notNullValue())
        assertThat(methodTypeForm.required, equalTo(false))
        assertThat(methodTypeForm.value, equalTo("password"))
        assertThat(methodTypeForm.mutable, equalTo(false))

        // Security Question
        Options secQnOption = authenticatorOptions.options().find {it.label == "Security Question"}
        assertThat(secQnOption, notNullValue())

        idForm = secQnOption.getValue().getForm().getValue().find {it.name == "id"}
        assertThat(idForm, notNullValue())
        assertThat(idForm.required, equalTo(true))
        assertThat(idForm.value, equalTo("aut2ihzk4hgf9sIQa1d6"))
        assertThat(idForm.mutable, equalTo(false))

        methodTypeForm = secQnOption.getValue().getForm().getValue().find {it.name == "methodType"}
        assertThat(methodTypeForm, notNullValue())
        assertThat(methodTypeForm.required, equalTo(false))
        assertThat(methodTypeForm.value, equalTo("security_question"))
        assertThat(methodTypeForm.mutable, equalTo(false))
    }

    @Test
    void testAnswerChallengeResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        Authenticator passwordAuthenticator = new Authenticator()
        passwordAuthenticator.setId("aut2ihzk2n15tsQnQ1d6")
        passwordAuthenticator.setMethodType("password")

        ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                .withStateHandle("stateHandle")
                .withAuthenticator(passwordAuthenticator)
                .build()

        final Response stubbedChallengeResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("challenge-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedChallengeResponse)

        IDXResponse passwordAuthenticatorChallengeResponse =
                idxClient.challenge(passwordAuthenticatorChallengeRequest, "href")

        assertThat(passwordAuthenticatorChallengeResponse, notNullValue())

        Credentials passwordCredentials = new Credentials()
        passwordCredentials.setPasscode("some-password".toCharArray())

        AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                .withStateHandle("stateHandle")
                .withCredentials(passwordCredentials)
                .build()

        final Response stubbedAnswerChallengeResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("answer-challenge-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedAnswerChallengeResponse)

        IDXResponse passwordAuthenticatorAnswerChallengeResponse =
                passwordAuthenticatorChallengeResponse.remediation().remediationOptions().first().proceed(idxClient, passwordAuthenticatorAnswerChallengeRequest)

        assertThat(passwordAuthenticatorAnswerChallengeResponse.stateHandle, notNullValue())
        assertThat(passwordAuthenticatorAnswerChallengeResponse.version, notNullValue())
        assertThat(passwordAuthenticatorAnswerChallengeResponse.expiresAt, equalTo("2020-10-29T21:17:36.000Z"))
        assertThat(passwordAuthenticatorAnswerChallengeResponse.intent, equalTo("LOGIN"))
        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation.type, equalTo("array"))

        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation().remediationOptions(), notNullValue())
        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation.value.first().rel, hasItemInArray("create-form"))
        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation.value.first().name, equalTo("select-authenticator-authenticate"))
        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/challenge"))
        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation.value.first().method, equalTo("POST"))
        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation.value.first().accepts, equalTo("application/ion+json; okta-version=1.0.0"))

        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation.value.first().form(), notNullValue())

        FormValue[] formValues = passwordAuthenticatorAnswerChallengeResponse.remediation().remediationOptions().first().form()

        Optional<FormValue> stateHandleForm = Arrays.stream(formValues)
                .filter({ x -> ("stateHandle" == x.getName()) })
                .findFirst()

        FormValue stateHandleFormValue = stateHandleForm.get()

        assertThat(stateHandleFormValue, notNullValue())
        assertThat(stateHandleFormValue.required, equalTo(true))
        assertThat(stateHandleFormValue.value, equalTo("025r9Yn758Z-zwhMGDm1saTaW1pVRy4t9oTxM7dLYE"))
        assertThat(stateHandleFormValue.visible, equalTo(false))
        assertThat(stateHandleFormValue.mutable, equalTo(false))

        RemediationOption authenticatorOption = passwordAuthenticatorChallengeResponse.remediation().remediationOptions()
                .find {it.name == "select-authenticator-authenticate"}

        assertThat(authenticatorOption.rel, hasItemInArray("create-form"))
        assertThat(authenticatorOption.href, equalTo("https://foo.oktapreview.com/idp/idx/challenge"))
        assertThat(authenticatorOption.method, equalTo("POST"))
        assertThat(authenticatorOption.form(), notNullValue())

        FormValue authenticatorOptions = authenticatorOption.form().find {it.name == "authenticator"}
        assertThat(authenticatorOptions, notNullValue())
        assertThat(authenticatorOptions.type, equalTo("object"))

        // Email
        Options emailOption = authenticatorOptions.options().find {it.label == "Email"}
        assertThat(emailOption, notNullValue())

        FormValue idForm = emailOption.getValue().getForm().getValue().find {it.name == "id"}
        assertThat(idForm, notNullValue())
        assertThat(idForm.required, equalTo(true))
        assertThat(idForm.value, equalTo("aut2ihzk1gHl7ynhd1d6"))
        assertThat(idForm.mutable, equalTo(false))

        FormValue methodTypeForm = emailOption.getValue().getForm().getValue().find {it.name == "methodType"}
        assertThat(methodTypeForm, notNullValue())
        assertThat(methodTypeForm.required, equalTo(false))
        assertThat(methodTypeForm.value, equalTo("email"))
        assertThat(methodTypeForm.mutable, equalTo(false))
    }

    @Test
    void testCancel() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedCancelResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("cancel-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedCancelResponse)

        IDXResponse cancelResponse = idxClient.cancel("stateHandle")

        assertThat(cancelResponse.stateHandle, notNullValue())
        assertThat(cancelResponse.version, notNullValue())
        assertThat(cancelResponse.expiresAt, notNullValue())
        assertThat(cancelResponse.intent, is("LOGIN"))

        assertThat(cancelResponse.remediation().type, is("array"))
        assertThat(cancelResponse.remediation().remediationOptions(), notNullValue())
        assertThat(cancelResponse.remediation.value.first().rel, hasItemInArray("create-form"))
        assertThat(cancelResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/identify"))
        assertThat(cancelResponse.remediation.value.first().name, equalTo("identify"))
        assertThat(cancelResponse.remediation.value.first().accepts, equalTo("application/ion+json; okta-version=1.0.0"))

        assertThat(cancelResponse.cancel, notNullValue())
        assertThat(cancelResponse.cancel.rel, hasItemInArray("create-form"))
        assertThat(cancelResponse.cancel.href, equalTo("https://foo.oktapreview.com/idp/idx/cancel"))
        assertThat(cancelResponse.cancel.name, equalTo("cancel"))
        assertThat(cancelResponse.cancel.accepts, equalTo("application/ion+json; okta-version=1.0.0"))

        assertThat(cancelResponse.app, notNullValue())
        assertThat(cancelResponse.app.type, is("object"))
        assertThat(cancelResponse.app.value.name, is("oidc_client"))
        assertThat(cancelResponse.app.value.label, is("test-app"))
        assertThat(cancelResponse.app.value.id, is("0oazsmpxZpVEg4chS2o4"))
    }

    @Test
    void testToken() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final IDXClientContext idxClientContext = new IDXClientContext(
                "codeVerifier", "codeChallenge", "interactionHandle", "state")

        final Response stubbedTokenResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("token-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedTokenResponse)

        TokenResponse tokenResponse = idxClient.token("tokenUrl","grantType", "interactionCode", idxClientContext)

        assertThat(tokenResponse, notNullValue())
        assertThat(tokenResponse.tokenType, is("Bearer"))
        assertThat(tokenResponse.expiresIn, is(3600))
        assertThat(tokenResponse.accessToken, notNullValue())
        assertThat(tokenResponse.refreshToken, notNullValue())
        assertThat(tokenResponse.idToken, notNullValue())
        assertThat(tokenResponse.scope, is("openid email"))
    }

    @Test
    void testSecondFactorSuccessResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        Credentials credentials = new Credentials()
        credentials.setPasscode("some-email-passcode".toCharArray())

        AnswerChallengeRequest secondFactorAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                .withStateHandle("stateHandle")
                .withCredentials(credentials)
                .build()

        final Response stubbedAnswerChallengeResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("success-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedAnswerChallengeResponse)

        IDXResponse secondFactorAuthenticatorAnswerChallengeResponse =
                idxClient.answerChallenge(secondFactorAuthenticatorAnswerChallengeRequest, "href")

        assertThat(secondFactorAuthenticatorAnswerChallengeResponse, notNullValue())
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.remediation(), nullValue())
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.stateHandle, notNullValue())
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.version, notNullValue())
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.expiresAt, equalTo("2020-10-30T23:49:21.000Z"))
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.intent, equalTo("LOGIN"))

        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.getSuccessWithInteractionCode(), notNullValue())
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.getSuccessWithInteractionCode().getRel(), notNullValue())
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.getSuccessWithInteractionCode().getName(), notNullValue())
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.getSuccessWithInteractionCode().getHref(), notNullValue())
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.getSuccessWithInteractionCode().getMethod(), is("POST"))
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.getSuccessWithInteractionCode().getValue(), notNullValue())
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.getSuccessWithInteractionCode().parseGrantType(), is("interaction_code"))
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.getSuccessWithInteractionCode().parseInteractionCode(), is("Txd_5odx08kzZ_oxeEbBk8PNjI5UDnTM2P1rMCmHDyA"))
    }

    @Test
    void testEnrollAuthenticatorResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        Authenticator secQnEnrollAuthenticator = new Authenticator()
        secQnEnrollAuthenticator.setId("autzvyil7o5nQqC5j2o4")
        secQnEnrollAuthenticator.setMethodType("security_question")

        EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                .withStateHandle("02JwRcw6oq-uS3iIMT9uikGHNiD0DDkyGsp6aPNYMA")
                .withAuthenticator(secQnEnrollAuthenticator)
                .build()

        final Response stubbedEnrollAuthenticatorResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("enroll-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedEnrollAuthenticatorResponse)

        IDXResponse enrollSecQnAuthenticatorResponse = idxClient.enroll(enrollRequest, "href")

        assertThat(enrollSecQnAuthenticatorResponse, notNullValue())
        assertThat(enrollSecQnAuthenticatorResponse.stateHandle, equalTo("02JwRcw6oq-uS3iIMT9uikGHNiD0DDkyGsp6aPNYMA"))
        assertThat(enrollSecQnAuthenticatorResponse.version, equalTo("1.0.0"))
        assertThat(enrollSecQnAuthenticatorResponse.expiresAt, equalTo("2020-12-10T19:06:34.000Z"))
        assertThat(enrollSecQnAuthenticatorResponse.intent, equalTo("LOGIN"))

        assertThat(enrollSecQnAuthenticatorResponse.remediation(), notNullValue())
        assertThat(enrollSecQnAuthenticatorResponse.remediation.value.first().rel, hasItemInArray("create-form"))
        assertThat(enrollSecQnAuthenticatorResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/challenge/answer"))
        assertThat(enrollSecQnAuthenticatorResponse.remediation.value.first().name, equalTo("enroll-authenticator"))
        assertThat(enrollSecQnAuthenticatorResponse.remediation.value.first().accepts, equalTo("application/ion+json; okta-version=1.0.0"))

        RemediationOption[] remediationOptions = enrollSecQnAuthenticatorResponse.remediation().remediationOptions()
        assertThat(remediationOptions, notNullValue())

        Optional<RemediationOption> remediationOptionsEnrollAuthenticatorOptional = Arrays.stream(remediationOptions)
                .filter({ x -> ("enroll-authenticator" == x.getName()) })
                .findFirst()
        RemediationOption remediationOptionsEnrollAuthenticatorOption = remediationOptionsEnrollAuthenticatorOptional.get()
        assertThat(remediationOptionsEnrollAuthenticatorOption, notNullValue())

        FormValue[] enrollAuthenticatorFormValues = remediationOptionsEnrollAuthenticatorOption.form()
        Optional<FormValue> enrollAuthenticatorFormOptional = Arrays.stream(enrollAuthenticatorFormValues)
                .filter({ x -> ("credentials" == x.getName()) })
                .findFirst()
        FormValue enrollAuthenticatorForm = enrollAuthenticatorFormOptional.get()
        assertThat(enrollAuthenticatorForm, notNullValue())
        assertThat(enrollAuthenticatorForm.options(), hasSize(2))

        Options[] enrollmentAuthenticatorOptions = enrollAuthenticatorForm.options()
        Optional<Options> chooseSecQnOptionOptional = Arrays.stream(enrollmentAuthenticatorOptions)
                .filter({ x -> ("Choose a security question" == x.getLabel()) })
                .findFirst()
        Options chooseSecQnOption = chooseSecQnOptionOptional.get()
        assertThat(chooseSecQnOption, notNullValue())
        assertThat(chooseSecQnOption.value.form.value, hasSize(2))
        assertThat(chooseSecQnOption.value.form.value[0].name, is("questionKey"))
        assertThat(chooseSecQnOption.value.form.value[0].label, is("Choose a security question"))
        assertThat(chooseSecQnOption.value.form.value[0].required, equalTo(true))
        assertThat(chooseSecQnOption.value.form.value[0].options, hasSize(19)) // default sec qn list
        assertThat(chooseSecQnOption.value.form.value[1].name, is("answer"))
        assertThat(chooseSecQnOption.value.form.value[1].label, is("Answer"))
        assertThat(chooseSecQnOption.value.form.value[1].required, equalTo(true))

        Optional<Options> createOwnSecQnOptionOptional = Arrays.stream(enrollmentAuthenticatorOptions)
                .filter({ x -> ("Create my own security question" == x.getLabel()) })
                .findFirst()
        Options createOwnSecQnOption = createOwnSecQnOptionOptional.get()
        assertThat(createOwnSecQnOption, notNullValue())
        assertThat(createOwnSecQnOption.value.form.value[0].name, is("questionKey"))
        assertThat(createOwnSecQnOption.value.form.value[0].label, nullValue())
        assertThat(createOwnSecQnOption.value.form.value[0].required, equalTo(true))
        assertThat(createOwnSecQnOption.value.form.value[1].name, is("question"))
        assertThat(createOwnSecQnOption.value.form.value[1].label, equalTo("Create a security question"))
        assertThat(createOwnSecQnOption.value.form.value[1].required, equalTo(true))
        assertThat(createOwnSecQnOption.value.form.value[2].name, is("answer"))
        assertThat(createOwnSecQnOption.value.form.value[2].label, equalTo("Answer"))
        assertThat(createOwnSecQnOption.value.form.value[2].required, equalTo(true))
        assertThat(createOwnSecQnOption.value.form.value, hasSize(3))
    }

    @Test
    void testEnrollUpdateUserProfile() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        UserProfile userProfile = new UserProfile()
        userProfile.getFields().put("test-key-1", "test-val-1")
        userProfile.getFields().put("test-key-2", "test-val-2")

        EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest = EnrollUserProfileUpdateRequestBuilder.builder()
                .withStateHandle("02JwRcw6oq-uS3iIMT9uikGHNiD0DDkyGsp6aPNYMA")
                .withUserProfile(userProfile)
                .build()

        final Response stubbedEnrollUserProfileUpdateResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("enroll-update-user-profile-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedEnrollUserProfileUpdateResponse)

        IDXResponse enrollUpdateUserProfileResponse = idxClient.enrollUpdateUserProfile(enrollUserProfileUpdateRequest, "href")

        assertThat(enrollUpdateUserProfileResponse, notNullValue())
        assertThat(enrollUpdateUserProfileResponse.remediation(), nullValue())
        assertThat(enrollUpdateUserProfileResponse.stateHandle, notNullValue())
        assertThat(enrollUpdateUserProfileResponse.version, notNullValue())
        assertThat(enrollUpdateUserProfileResponse.expiresAt, equalTo("2020-12-11T18:42:30.000Z"))
        assertThat(enrollUpdateUserProfileResponse.intent, equalTo("LOGIN"))

        assertThat(enrollUpdateUserProfileResponse.getSuccessWithInteractionCode(), notNullValue())
        assertThat(enrollUpdateUserProfileResponse.getSuccessWithInteractionCode().getRel(), notNullValue())
        assertThat(enrollUpdateUserProfileResponse.getSuccessWithInteractionCode().getName(), notNullValue())
        assertThat(enrollUpdateUserProfileResponse.getSuccessWithInteractionCode().getHref(), notNullValue())
        assertThat(enrollUpdateUserProfileResponse.getSuccessWithInteractionCode().getMethod(), is("POST"))
        assertThat(enrollUpdateUserProfileResponse.getSuccessWithInteractionCode().getValue(), notNullValue())
        assertThat(enrollUpdateUserProfileResponse.getSuccessWithInteractionCode().parseGrantType(), is("interaction_code"))
        assertThat(enrollUpdateUserProfileResponse.getSuccessWithInteractionCode().parseInteractionCode(), is("ygc5TLrx6a8AXAnxliW9Xd50ZODCTxO3imJ_I4-tmcg"))
    }

    @Test
    void testWebAuthnAnswerChallengeResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        // build answer fingerprint authenticator challenge request
        Credentials credentials = new Credentials()
        credentials.setAuthenticatorData("5vIi/yA..")
        credentials.setClientData("eyJjaGFsbGVuZ2UiO...")
        credentials.setSignatureData("jaZSjGS6+jiVH...")

        AnswerChallengeRequest fingerprintAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                .withStateHandle("uS3iIMT9uikGHNiD0DDkyGsp6aMKIOPOK")
                .withCredentials(credentials)
                .build()

        final Response stubbedAnswerChallengeResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("answer-challenge-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedAnswerChallengeResponse)

        IDXResponse fingerprintAuthenticatorAnswerChallengeResponse = idxClient.answerChallenge(fingerprintAuthenticatorAnswerChallengeRequest, "href")

        assertThat(fingerprintAuthenticatorAnswerChallengeResponse.stateHandle, notNullValue())
        assertThat(fingerprintAuthenticatorAnswerChallengeResponse.version, notNullValue())
        assertThat(fingerprintAuthenticatorAnswerChallengeResponse.expiresAt, equalTo("2020-10-29T21:17:36.000Z"))
        assertThat(fingerprintAuthenticatorAnswerChallengeResponse.intent, equalTo("LOGIN"))
        assertThat(fingerprintAuthenticatorAnswerChallengeResponse.remediation.type, equalTo("array"))
    }

    @Test
    void testSkipOptionalAuthenticatorEnrollment() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest = SkipAuthenticatorEnrollmentRequestBuilder.builder()
                .withStateHandle("02EPfpFV_56cDmc4r1BQNhYFW_WEbViA6rd1YRwCRH")
                .build()

        final Response stubbedSkipAuthEnrollmentResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("skip-optional-authenticator-enrollment-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedSkipAuthEnrollmentResponse)

        IDXResponse skipAuthEnrollmentResponse = idxClient.skip(skipAuthenticatorEnrollmentRequest, "href")

        assertThat(skipAuthEnrollmentResponse, notNullValue())
        assertThat(skipAuthEnrollmentResponse.remediation(), nullValue())
        assertThat(skipAuthEnrollmentResponse.stateHandle, notNullValue())
        assertThat(skipAuthEnrollmentResponse.version, notNullValue())
        assertThat(skipAuthEnrollmentResponse.expiresAt, equalTo("2020-12-21T20:41:27.000Z"))
        assertThat(skipAuthEnrollmentResponse.intent, equalTo("LOGIN"))

        assertThat(skipAuthEnrollmentResponse.getSuccessWithInteractionCode(), notNullValue())
        assertThat(skipAuthEnrollmentResponse.getSuccessWithInteractionCode().getRel(), notNullValue())
        assertThat(skipAuthEnrollmentResponse.getSuccessWithInteractionCode().getName(), notNullValue())
        assertThat(skipAuthEnrollmentResponse.getSuccessWithInteractionCode().getHref(), notNullValue())
        assertThat(skipAuthEnrollmentResponse.getSuccessWithInteractionCode().getMethod(), is("POST"))
        assertThat(skipAuthEnrollmentResponse.getSuccessWithInteractionCode().getValue(), notNullValue())
        assertThat(skipAuthEnrollmentResponse.getSuccessWithInteractionCode().parseGrantType(), is("interaction_code"))
        assertThat(skipAuthEnrollmentResponse.getSuccessWithInteractionCode().parseInteractionCode(), is("Txd_5odx08kzZ_oxeEbBk8PNjI5UDnTM2P1rMCmHDyA"))
    }

    @Test
    void testRecover() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedRecoverResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("recover-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedRecoverResponse)

        RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
                .withStateHandle("02X1oUMHSpVb_MTxvhmr8-5Es8Rcizy4Xq4OSr3mkH")
                .build()

        IDXResponse recoverResponse = idxClient.recover(recoverRequest, "href")

        assertThat(recoverResponse.stateHandle, notNullValue())
        assertThat(recoverResponse.version, notNullValue())
        assertThat(recoverResponse.expiresAt, notNullValue())
        assertThat(recoverResponse.intent, is("LOGIN"))

        assertThat(recoverResponse.remediation().type, is("array"))
        assertThat(recoverResponse.remediation().remediationOptions(), notNullValue())
        assertThat(recoverResponse.remediation.value.first().rel, hasItemInArray("create-form"))
        assertThat(recoverResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/challenge/answer"))
        assertThat(recoverResponse.remediation.value.first().name, equalTo("challenge-authenticator"))
        assertThat(recoverResponse.remediation.value.first().accepts, equalTo("application/json; okta-version=1.0.0"))

        // authenticatorEnrollments
        assertThat(recoverResponse.authenticatorEnrollments, notNullValue())

        AuthenticatorEnrollment secQnAuthEnrollment = recoverResponse.authenticatorEnrollments.values.find {it.type == "security_question"}
        assertThat(secQnAuthEnrollment, notNullValue())
        assertThat(secQnAuthEnrollment.profile, notNullValue())
        assertThat(secQnAuthEnrollment.id, equalTo("qae3m4ksak2mzReE60g7"))
        assertThat(secQnAuthEnrollment.type, equalTo("security_question"))
        assertThat(secQnAuthEnrollment.displayName, equalTo("Security Question"))
        assertThat(secQnAuthEnrollment.methods, notNullValue())
        assertThat(secQnAuthEnrollment.methods.first(), notNullValue())
        assertThat(secQnAuthEnrollment.methods.first().type, equalTo("security_question"))

        assertThat(recoverResponse.cancel, notNullValue())
        assertThat(recoverResponse.cancel.rel, hasItemInArray("create-form"))
        assertThat(recoverResponse.cancel.href, equalTo("https://foo.oktapreview.com/idp/idx/cancel"))
        assertThat(recoverResponse.cancel.name, equalTo("cancel"))
        assertThat(recoverResponse.cancel.accepts, equalTo("application/json; okta-version=1.0.0"))

        assertThat(recoverResponse.app, notNullValue())
        assertThat(recoverResponse.app.type, is("object"))
        assertThat(recoverResponse.app.value.name, is("okta_enduser"))
        assertThat(recoverResponse.app.value.label, is("Okta Dashboard"))
        assertThat(recoverResponse.app.value.id, is("DEFAULT_APP"))
    }

    @Test
    void testRegistration() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedInteractResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("interact-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedInteractResponse)

        IDXClientContext idxClientContext = idxClient.interact()

        final Response stubbedIntrospectResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("introspect-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedIntrospectResponse)

        IDXResponse introspectResponse = idxClient.introspect(idxClientContext)

        assertThat(introspectResponse.remediation().remediationOptions(), notNullValue())
        assertThat(introspectResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/identify"))

        RemediationOption remediationOption =
                introspectResponse.remediation().remediationOptions().find({ it -> (it.name == "select-enroll-profile") })

        EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                .withStateHandle("02tYS1NHhCPLcOpT3GByBBRHmGU63p7LGRXJx5cOvp")
                .build()

        final Response stubbedEnrollProfileResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("enroll-user-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedEnrollProfileResponse)

        IDXResponse enrollResponse = remediationOption.proceed(idxClient, enrollRequest)

        assertThat(enrollResponse.remediation().remediationOptions(), notNullValue())
        assertThat(enrollResponse.remediation.value.first().name, equalTo("enroll-profile"))
        assertThat(enrollResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/enroll/new"))

        remediationOption = enrollResponse.remediation().remediationOptions().find({ it -> (it.name == "enroll-profile") })

        // supply only the "required" attributes
        UserProfile up = new UserProfile()
        up.setLastName("Coder")
        up.setFirstName("Joe")
        Random randomGenerator = new Random()
        int randomInt = randomGenerator.nextInt(1000)
        up.setEmail("joe.coder" + randomInt + "@example.com")
        up.addAttribute("age", "40")
        up.addAttribute("sex", "Male")

        EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest = EnrollUserProfileUpdateRequestBuilder.builder()
                .withUserProfile(up)
                .withStateHandle("02tYS1NHhCPLcOpT3GByBBRHmGU63p7LGRXJx5cOvp")
                .build()

        final Response stubbedEnrollNewResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("enroll-profile-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedEnrollNewResponse)

        IDXResponse enrollProfileResponse = remediationOption.proceed(idxClient, enrollUserProfileUpdateRequest)

        assertThat(enrollProfileResponse.remediation().remediationOptions(), notNullValue())
        assertThat(enrollProfileResponse.remediation.value.first().name, equalTo("select-authenticator-enroll"))
        assertThat(enrollProfileResponse.remediation.value.first().href, equalTo("https://foo.oktapreview.com/idp/idx/credential/enroll"))
    }

    @Test
    void testSkipAuthenticatorEnrollment() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        Credentials credentials = new Credentials();
        credentials.setPasscode("password".toCharArray())

        AnswerChallengeRequest answerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                .withStateHandle("02C563D3IFfsob9PQlzC70FO_H9FLKGMturswYm1at")
                .withCredentials(credentials)
                .build()

        final Response stubbedAnswerAuthenticatorEnrollmentChallengeResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("answer-authenticator-enrollment-challenge-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedAnswerAuthenticatorEnrollmentChallengeResponse)

        IDXResponse idxResponse = idxClient.answerChallenge(answerChallengeRequest, "href")

        RemediationOption remediationOption = idxResponse.remediation().remediationOptions().find { it -> it.name == "skip"}

        final Response stubbedSkipAuthenticatorEnrollmentResponse = new DefaultResponse(
                200,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("success-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedSkipAuthenticatorEnrollmentResponse)

        SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest = SkipAuthenticatorEnrollmentRequestBuilder.builder()
                .withStateHandle("stateHandle")
                .build()

        idxResponse = remediationOption.proceed(idxClient, skipAuthenticatorEnrollmentRequest)
        assertThat(idxResponse.remediation(), nullValue())
    }

    @Test
    void testInteractErrorResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedInteractResponse = new DefaultResponse(
                400,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("interact-error-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedInteractResponse)

        try {
            idxClient.interact()
        } catch (ProcessingException e) {
            String interactUrl = normalizedIssuerUri(clientConfiguration.getIssuer(),"/v1/interact")
            assertThat(e.getHttpStatus(), is(400))
            assertThat(e.getMessage(), is("Request to " + interactUrl + " failed. HTTP status: 400"))
            assertThat(e.getErrorResponse(), notNullValue())
            assertThat(e.getErrorResponse().getError(), is("invalid_request"))
            assertThat(e.getErrorResponse().getErrorDescription(), is("PKCE code challenge is required when the token endpoint authentication method is 'NONE'."))
        }
    }

    @Test
    void testIntrospectErrorResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final IDXClientContext idxClientContext = new IDXClientContext(
                "codeVerifier", "codeChallenge", "expiredInteractionHandle", "state")

        final Response stubbedIntrospectResponse = new DefaultResponse(
                401,
                MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
                new FileInputStream(getClass().getClassLoader().getResource("introspect-error-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedIntrospectResponse)

        try {
            idxClient.introspect(idxClientContext)
        } catch (ProcessingException e) {
            assertThat(e.getHttpStatus(), is(401))
            assertThat(e.getMessage(), is("Request to " + clientConfiguration.getBaseUrl() + "/idp/idx/introspect failed. HTTP status: 401"))
            assertThat(e.getErrorResponse(), notNullValue())
            assertThat(e.getErrorResponse().getMessages().getValue().first().message, is("The session has expired."))
            assertThat(e.getErrorResponse().getMessages().getValue().first().value, is("ERROR"))
        }
    }

    @Test
    void testTokenErrorResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final IDXClientContext idxClientContext = new IDXClientContext(
                "codeVerifier", "codeChallenge","interactionHandle", "state")

        final Response stubbedTokenResponse = new DefaultResponse(
                400,
                MediaType.valueOf("application/json"),
                new FileInputStream(getClass().getClassLoader().getResource("token-error-response.json").getFile()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedTokenResponse)

        try {
            idxClient.token("tokenUrl", "grantType", "interactionCode", idxClientContext)
        } catch (ProcessingException e) {
            assertThat(e.getMessage(), is("Request to tokenUrl failed. HTTP status: 400"))
            assertThat(e.getHttpStatus(), is(400))
            assertThat(e.getErrorResponse(), notNullValue())
            assertThat(e.getErrorResponse().getError(), is("invalid_grant"))
            assertThat(e.getErrorResponse().getErrorDescription(), is("PKCE verification failed."))
        }
    }

    @Test
    void testServiceUnavailableErrorResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedTokenResponse = new DefaultResponse(
                500,
                MediaType.valueOf("text/plain"),
                new ByteArrayInputStream("Service Unavailable".getBytes()),
                -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedTokenResponse)

        try {
            idxClient.interact()
        } catch (ProcessingException e) {
            String interactUrl = normalizedIssuerUri(clientConfiguration.getIssuer(),"/v1/interact")
            assertThat(e.getHttpStatus(), is(500))
            assertThat(e.getMessage(), is("Request to " + interactUrl + " failed. HTTP status: 500"))
        }
    }

    @Test
    void testClientHttpException() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
                new BaseIDXClient(getClientConfiguration(), requestExecutor)

        when(requestExecutor.executeRequest(any(Request.class))).thenThrow(new HttpException("Connection failed!"))

        try {
            idxClient.interact()
        } catch (ProcessingException e) {
            assertThat(e.getMessage(), is("com.okta.commons.http.HttpException: Connection failed!"))
        }
    }

    ClientConfiguration getClientConfiguration() {
        ClientConfiguration clientConfiguration = new ClientConfiguration()
        clientConfiguration.setIssuer("http://example.com")
        clientConfiguration.setClientId("test-client-id")
        clientConfiguration.setClientSecret("test-client-secret")
        clientConfiguration.setScopes(["test-scope"] as Set)
        return clientConfiguration
    }
}
