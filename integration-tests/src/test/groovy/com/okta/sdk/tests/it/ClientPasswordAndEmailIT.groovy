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

import com.google.common.collect.Sets
import com.okta.sdk.api.client.Clients
import com.okta.sdk.api.client.OktaIdentityEngineClient
import com.okta.sdk.api.model.*
import com.okta.sdk.api.request.AnswerChallengeRequest
import com.okta.sdk.api.request.ChallengeRequest
import com.okta.sdk.api.request.IdentifyRequest
import com.okta.sdk.api.response.OktaIdentityEngineResponse

import javax.swing.*

import static org.hamcrest.MatcherAssert.assertThat
import static org.hamcrest.Matchers.notNullValue
import static org.hamcrest.Matchers.nullValue

class ClientPasswordAndEmailIT {

    //@Test
    void testHappyPath_SecurityQuestionAndEmailAuth() {

        final OktaIdentityEngineClient client = Clients.builder()
            .setIssuer("https://devex-idx-testing.oktapreview.com")
            .setClientId("test-client-id")
            .setScopes(Sets.newHashSet("test-scope-1", "test-scope-2"))
            .build()

        def stateHandle = JOptionPane.showInputDialog("Enter stateHandle: ")
        assertThat(stateHandle, notNullValue())

        // 1. invoke introspect endpoint with the state handle
        OktaIdentityEngineResponse introspectResponse = client.introspect(stateHandle)
        assertThat(introspectResponse, notNullValue())

        final String identifier = JOptionPane.showInputDialog("Enter identifier (email): ")
        assertThat(identifier, notNullValue())

        // 2. invoke identify endpoint & get remediation options
        IdentifyRequest identifyRequest = new IdentifyRequest(identifier, stateHandle, false)
        OktaIdentityEngineResponse identifyResponse = client.identify(identifyRequest)

        assertThat(identifyResponse, notNullValue())
        assertThat(identifyResponse.remediation(), notNullValue())
        assertThat(identifyResponse.remediation().remediationOptions(), notNullValue())

        RemediationOption[] identifyRemediationOptions = identifyResponse.remediation().remediationOptions()
        Optional<RemediationOption> identifyRemediationOptionOptional = Arrays.stream(identifyRemediationOptions)
            .filter({ x -> ("select-authenticator-authenticate" == x.getName()) })
            .findFirst()

        // populate methodType -> id mapping
        Map<String, String> authenticatorOptionsMap = getAuthenticatorOptions(identifyRemediationOptionOptional.get())

        // password authentication (step-1)

        // challenge
        ChallengeRequest passwordAuthenticatorChallengeRequest =
            new ChallengeRequest("test-state-handle", new Authenticator(authenticatorOptionsMap.get("password"), "password"))
        OktaIdentityEngineResponse passwordAuthenticatorChallengeResponse = identifyRemediationOptionOptional.get().proceed(client, passwordAuthenticatorChallengeRequest)

        assertThat(passwordAuthenticatorChallengeResponse, notNullValue())
        assertThat(passwordAuthenticatorChallengeResponse.remediation(), notNullValue())
        assertThat(passwordAuthenticatorChallengeResponse.remediation().remediationOptions(), notNullValue())

        RemediationOption[] passwordAuthenticatorChallengeResponseRemediationOptions = passwordAuthenticatorChallengeResponse.remediation().remediationOptions()
        Optional<RemediationOption> challengeAuthenticatorRemediationOption = Arrays.stream(passwordAuthenticatorChallengeResponseRemediationOptions)
            .filter({ x -> ("challenge-authenticator" == x.getName()) })
            .findFirst()

        // answer challenge
        def password = JOptionPane.showInputDialog("Enter Password: ")
        assertThat(password, notNullValue())

        AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = new AnswerChallengeRequest(stateHandle, new Credentials(password, null))
        OktaIdentityEngineResponse passwordAuthenticatorAnswerChallengeResponse = challengeAuthenticatorRemediationOption.get().proceed(client, passwordAuthenticatorAnswerChallengeRequest)

        assertThat(passwordAuthenticatorAnswerChallengeResponse, notNullValue())
        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation(), notNullValue())
        assertThat(passwordAuthenticatorAnswerChallengeResponse.remediation().remediationOptions(), notNullValue())

        RemediationOption[] passwordAuthenticatorAnswerChallengeResponseRemediationOptions = passwordAuthenticatorAnswerChallengeResponse.remediation().remediationOptions()

        // email authentication (step 2)

        // challenge
        Optional<RemediationOption> emailAuthenticatorRemediationOption = Arrays.stream(passwordAuthenticatorAnswerChallengeResponseRemediationOptions)
            .filter({ x -> ("select-authenticator-authenticate" == x.getName()) })
            .findFirst()

        ChallengeRequest emailAuthenticatorChallengeRequest = new ChallengeRequest(stateHandle, new Authenticator(authenticatorOptionsMap.get("email"), "email"))
        OktaIdentityEngineResponse emailAuthenticatorChallengeResponse = emailAuthenticatorRemediationOption.get().proceed(client, emailAuthenticatorChallengeRequest)

        assertThat(emailAuthenticatorChallengeResponse, notNullValue())
        assertThat(emailAuthenticatorChallengeResponse.remediation(), notNullValue())
        assertThat(emailAuthenticatorChallengeResponse.remediation().remediationOptions(), notNullValue())

        RemediationOption[] emailAuthenticatorChallengeResponseRemediationOptions = emailAuthenticatorChallengeResponse.remediation().remediationOptions()
        challengeAuthenticatorRemediationOption = Arrays.stream(emailAuthenticatorChallengeResponseRemediationOptions)
            .filter({ x -> ("challenge-authenticator" == x.getName()) })
            .findFirst()

        // answer challenge
        def emailPasscode = JOptionPane.showInputDialog("Enter email passcode: ")
        assertThat(emailPasscode, notNullValue())

        AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = new AnswerChallengeRequest(stateHandle, new Credentials(emailPasscode, null))
        OktaIdentityEngineResponse emailAuthenticatorAnswerChallengeResponse = challengeAuthenticatorRemediationOption.get().proceed(client, emailAuthenticatorAnswerChallengeRequest)

        assertThat(emailAuthenticatorAnswerChallengeResponse, notNullValue())
        // no more remediation steps and we have completed successfully!
        assertThat(emailAuthenticatorAnswerChallengeResponse.remediation(), nullValue())
        assertThat(emailAuthenticatorAnswerChallengeResponse.getSuccess(), notNullValue())
    }

    // helper to extract authenticator options from remediation options in oie response

    static Map<String, String> getAuthenticatorOptions(RemediationOption remediationOption) {

        // store methodType -> id mapping
        Map<String, String> authenticatorOptionsMap = new HashMap<>()

        FormValue[] formValues = remediationOption.form()

        Optional<FormValue> formValueOptional = Arrays.stream(formValues)
            .filter({ x -> ("authenticator" == x.getName()) })
            .findFirst()

        if (formValueOptional.isPresent()) {
            Options[] options = formValueOptional.get().options()

            for (Options option : options) {
                String key = null, val = null
                FormValue[] optionFormValues = option.getValue().getForm().getValue()
                for (FormValue formValue : optionFormValues) {
                    if (formValue.getName() == "methodType") {
                        key = String.valueOf(formValue.getValue())
                    }
                    if (formValue.getName() == "id") {
                        val = String.valueOf(formValue.getValue())
                    }
                }
                authenticatorOptionsMap.put(key, val)
            }
        }
        return authenticatorOptionsMap
    }

}
