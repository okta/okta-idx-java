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

import com.okta.commons.http.DefaultResponse
import com.okta.commons.http.MediaType
import com.okta.commons.http.Request
import com.okta.commons.http.RequestExecutor
import com.okta.commons.http.Response
import com.okta.sdk.api.client.IDXClient
import com.okta.sdk.api.model.Authenticator
import com.okta.sdk.api.model.AuthenticatorEnrollment
import com.okta.sdk.api.model.Credentials
import com.okta.sdk.api.model.FormValue
import com.okta.sdk.api.model.Options
import com.okta.sdk.api.model.RemediationOption
import com.okta.sdk.api.request.AnswerChallengeRequest
import com.okta.sdk.api.request.AnswerChallengeRequestBuilder
import com.okta.sdk.api.request.ChallengeRequest
import com.okta.sdk.api.request.ChallengeRequestBuilder
import com.okta.sdk.api.request.IdentifyRequest
import com.okta.sdk.api.request.IdentifyRequestBuilder
import com.okta.sdk.api.response.InteractResponse
import com.okta.sdk.api.response.IDXResponse
import com.okta.sdk.impl.config.ClientConfiguration
import org.testng.annotations.Test

import static org.hamcrest.Matchers.is
import static org.mockito.Mockito.any
import static org.mockito.Mockito.mock
import static org.mockito.Mockito.when

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.equalTo
import static org.hamcrest.Matchers.hasItemInArray
import static org.hamcrest.Matchers.notNullValue
import static org.hamcrest.Matchers.nullValue

class BaseIDXClientTest {

    @Test
    void testInteractResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
            new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedResponse = new DefaultResponse(
            200,
            MediaType.valueOf("application/json"),
            new FileInputStream(getClass().getClassLoader().getResource("interact-response.json").getFile()),
            -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedResponse)

        InteractResponse response = idxClient.interact()

        assertThat(response, notNullValue())
        assertThat(response.getInteractionHandle(), is("003Q14X7li"))
    }

    @Test
    void testIntrospectResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
            new BaseIDXClient(getClientConfiguration(), requestExecutor)

        final Response stubbedResponse = new DefaultResponse(
            200,
            MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
            new FileInputStream(getClass().getClassLoader().getResource("introspect-response.json").getFile()),
            -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedResponse)

        IDXResponse response = idxClient.introspect(Optional.of("interactionHandle"))

        assertThat(response, notNullValue())
        assertThat(response.remediation(), notNullValue())
        assertThat(response.getMessages(), nullValue())
        assertThat(response.remediation().remediationOptions(), notNullValue())

        assertThat(response.expiresAt, equalTo("2020-10-31T01:42:02.000Z"))
        assertThat(response.intent, equalTo("LOGIN"))
        assertThat(response.remediation.type, equalTo("array"))
        assertThat(response.remediation.value.first().rel, hasItemInArray("create-form"))
        assertThat(response.remediation.value.first().name, equalTo("identify"))
        assertThat(response.remediation.value.first().href, equalTo("https://devex-idx-testing.oktapreview.com/idp/idx/identify"))
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

        final Response stubbedIntrospectResponse = new DefaultResponse(
            200,
            MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
            new FileInputStream(getClass().getClassLoader().getResource("introspect-response.json").getFile()),
            -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedIntrospectResponse)

        IDXResponse introspectResponse = idxClient.introspect(Optional.of("interactionHandle"))

        assertThat(introspectResponse.remediation().remediationOptions(), notNullValue())
        assertThat(introspectResponse.remediation.value.first().href, equalTo("https://devex-idx-testing.oktapreview.com/idp/idx/identify"))

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

        AuthenticatorEnrollment emailAuthEnrollment = identifyResponse.authenticatorEnrollments.value.find {it.type == "email"}
        assertThat(emailAuthEnrollment, notNullValue())
        assertThat(emailAuthEnrollment.profile, notNullValue())
        assertThat(emailAuthEnrollment.id, equalTo("eae3iyi3yzHZN4Cji1d6"))
        assertThat(emailAuthEnrollment.type, equalTo("email"))
        assertThat(emailAuthEnrollment.displayName, equalTo("Email"))
        assertThat(emailAuthEnrollment.profile.email, notNullValue())
        assertThat(emailAuthEnrollment.methods, notNullValue())
        assertThat(emailAuthEnrollment.methods.first(), notNullValue())
        assertThat(emailAuthEnrollment.methods.first().type, equalTo("email"))

        AuthenticatorEnrollment passwordAuthEnrollment = identifyResponse.authenticatorEnrollments.value.find {it.type == "password"}
        assertThat(passwordAuthEnrollment, notNullValue())
        assertThat(passwordAuthEnrollment.profile, nullValue())
        assertThat(passwordAuthEnrollment.id, equalTo("laekusi77LNcWg2rX1d5"))
        assertThat(passwordAuthEnrollment.type, equalTo("password"))
        assertThat(passwordAuthEnrollment.displayName, equalTo("Password"))
        assertThat(passwordAuthEnrollment.methods, notNullValue())
        assertThat(passwordAuthEnrollment.methods.first(), notNullValue())
        assertThat(passwordAuthEnrollment.methods.first().type, equalTo("password"))

        AuthenticatorEnrollment secQnAuthEnrollment = identifyResponse.authenticatorEnrollments.value.find {it.type == "security_question"}
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

        final Response stubbedIntrospectResponse = new DefaultResponse(
            200,
            MediaType.valueOf("application/ion+json; okta-version=1.0.0"),
            new FileInputStream(getClass().getClassLoader().getResource("introspect-response.json").getFile()),
            -1)

        when(requestExecutor.executeRequest(any(Request.class))).thenReturn(stubbedIntrospectResponse)

        IDXResponse introspectResponse = idxClient.introspect(Optional.of("interactionHandle"))

        assertThat(introspectResponse.remediation().remediationOptions(), notNullValue())
        assertThat(introspectResponse.remediation.value.first().href, equalTo("https://devex-idx-testing.oktapreview.com/idp/idx/identify"))

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
        assertThat(identifyResponse.remediation.value.first().href, equalTo("https://devex-idx-testing.oktapreview.com/idp/idx/challenge"))
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
        assertThat(passwordAuthenticatorChallengeResponse.remediation.value.first().href, equalTo("https://devex-idx-testing.oktapreview.com/idp/idx/challenge/answer"))
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
        assertThat(authenticatorOption.href, equalTo("https://devex-idx-testing.oktapreview.com/idp/idx/challenge"))
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
            idxClient.challenge(passwordAuthenticatorChallengeRequest)

        assertThat(passwordAuthenticatorChallengeResponse, notNullValue())

        Credentials passwordCredentials = new Credentials()
        passwordCredentials.setPasscode("some-password")

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
        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation.value.first().href, equalTo("https://devex-idx-testing.oktapreview.com/idp/idx/challenge"))
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
        assertThat(authenticatorOption.href, equalTo("https://devex-idx-testing.oktapreview.com/idp/idx/challenge"))
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
    void testSecondFactorSuccessResponse() {

        RequestExecutor requestExecutor = mock(RequestExecutor)

        final IDXClient idxClient =
            new BaseIDXClient(getClientConfiguration(), requestExecutor)

        Credentials credentials = new Credentials()
        credentials.setPasscode("some-email-passcode")

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
            idxClient.answerChallenge(secondFactorAuthenticatorAnswerChallengeRequest)

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
        assertThat(secondFactorAuthenticatorAnswerChallengeResponse.getSuccessWithInteractionCode().parseClientId(), is("0oa3jxy2kpqZs9fOU0g7"))
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
