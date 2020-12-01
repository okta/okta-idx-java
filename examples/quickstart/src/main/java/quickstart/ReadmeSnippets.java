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
package quickstart;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.okta.sdk.api.client.Clients;
import com.okta.sdk.api.client.IDXClient;
import com.okta.sdk.api.exception.ProcessingException;
import com.okta.sdk.api.model.Authenticator;
import com.okta.sdk.api.model.Credentials;
import com.okta.sdk.api.model.FormValue;
import com.okta.sdk.api.model.RemediationOption;
import com.okta.sdk.api.request.AnswerChallengeRequest;
import com.okta.sdk.api.request.AnswerChallengeRequestBuilder;
import com.okta.sdk.api.request.ChallengeRequest;
import com.okta.sdk.api.request.ChallengeRequestBuilder;
import com.okta.sdk.api.request.EnrollRequest;
import com.okta.sdk.api.request.EnrollRequestBuilder;
import com.okta.sdk.api.request.IdentifyRequestBuilder;
import com.okta.sdk.api.response.IDXResponse;
import com.okta.sdk.api.response.InteractResponse;
import com.okta.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Scanner;

/**
 * Example snippets used for this projects README.md.
 * <p>
 * Manually run {@code mvn okta-code-snippet:snip} after changing this file to update the README.md.
 */
@SuppressWarnings({"unused"})
public class ReadmeSnippets {

    private static final Logger log = LoggerFactory.getLogger(ReadmeSnippets.class);

    private static final IDXClient client = Clients.builder().build();

    private static IDXResponse idxResponse;
    private static RemediationOption remediationOption;

    private void createClient() {
        IDXClient client = Clients.builder()
                .setIssuer("https://{yourOktaDomain}/oauth2/{authorizationServerId}") // e.g. https://foo.okta.com/oauth2/default, https://foo.okta.com/oauth2/ausar5vgt5TSDsfcJ0h7
                .setClientId("{clientId}")
                .setClientSecret("{clientSecret}")
                .setScopes(new HashSet<>(Arrays.asList("openid", "email")))
                .setRedirectUri("{redirectUri}") // must match the redirect uri in client app settings/console
                .build();
    }

    private void getInteractionHandle() throws ProcessingException {
        InteractResponse interactResponse = client.interact();
        String interactHandle = interactResponse.getInteractionHandle();
    }

    private void exchangeInteractionHandleForStateHandle() throws ProcessingException {
        // optional with interactionHandle or empty; if empty, a new interactionHandle will be obtained
        idxResponse = client.introspect(Optional.of("{interactHandle}"));
        String stateHandle = idxResponse.getStateHandle();
    }

    private void printRawIdxResponse() throws JsonProcessingException {
        String rawResponse = idxResponse.raw();
    }

    private void checkRemediationOptions() {
        // check remediation options to continue the flow
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();
        FormValue[] formValues = remediationOption.form();
    }

    private void invokeIdentifyWithOrWithoutCredentials() throws ProcessingException {

        idxResponse = client.introspect(Optional.of("{interactHandle}"));
        String stateHandle = idxResponse.getStateHandle();

        // check remediation options to continue the flow
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();
        FormValue[] formValues = remediationOption.form();

        // check if 'credentials' is required to be sent in identify API request (next step)
        Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                .filter(x -> "credentials".equals(x.getName()))
                .findFirst();

        if (credentialsFormValueOptional.isPresent()) {
            FormValue credentialsFormValue = credentialsFormValueOptional.get();

            if (credentialsFormValue.isRequired()) {
                // credentials are REQUIRED
                Credentials credentials = new Credentials();
                credentials.setPasscode("{password}".toCharArray());

                idxResponse = client.identify(IdentifyRequestBuilder.builder()
                        .withIdentifier("{identifier}") // email
                        .withCredentials(credentials)
                        .withStateHandle(stateHandle)
                        .build());
            }
        } else {
            // credentials are not necessary; so sending just the identifier
            idxResponse = client.identify(IdentifyRequestBuilder.builder()
                    .withIdentifier("{identifier}") // email
                    .withStateHandle(stateHandle)
                    .build());
        }
    }

    private void checkRemediationOptionsAndSelectAuthenticator() {
        // check remediation options to continue the flow
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();

        // select an authenticator
        Authenticator authenticator = new Authenticator();
        authenticator.setId("{id}"); // authenticator's 'id' value from remediation option above
        authenticator.setMethodType("{methodType}"); // authenticator's 'methodType' value from remediation option above
    }

    private void invokeChallengeAuthenticator() throws ProcessingException {
        Authenticator passwordAuthenticator = new Authenticator();
        passwordAuthenticator.setId("{id}");
        passwordAuthenticator.setMethodType("{methodType}");

        // build password authenticator challenge request
        ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                .withAuthenticator(passwordAuthenticator)
                .withStateHandle("{stateHandle}")
                .build();

        // proceed
        idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest); // remediationOption object is a reference to the previous step's remediation options
    }

    private void invokeAnswerChallengeAuthenticator() throws ProcessingException {
        // check remediation options of authenticator challenge response (prior step)
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "challenge-authenticator".equals(x.getName()))
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();

        Credentials credentials = new Credentials();
        credentials.setPasscode("{emailPasscode}".toCharArray());  // passcode received in email

        // build answer email authenticator challenge request
        AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                .withStateHandle("{stateHandle}")
                .withCredentials(credentials)
                .build();

        // proceed
        idxResponse = remediationOption.proceed(client, emailAuthenticatorAnswerChallengeRequest);
    }

    private void cancel() throws ProcessingException {
        // invalidates the supplied stateHandle and obtains a fresh one
        idxResponse = client.cancel("{stateHandle}");
    }

    private void enrollAuthenticator() {
        // check remediation options to continue the flow
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "select-authenticator-enroll".equals(x.getName()))
                .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();

        // select an authenticator
        Authenticator authenticator = new Authenticator();
        authenticator.setId("{id}");                 // authenticator's 'id' value from remediation option above
        authenticator.setMethodType("{methodType}"); // authenticator's 'methodType' value from remediation option above

        // build enroll request
        EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                .withAuthenticator(authenticator)
                .withStateHandle("{stateHandle}")
                .build();

        // proceed
        idxResponse = remediationOption.proceed(client, enrollRequest);
    }

    private void checkForLoginSuccess() {
        if (idxResponse.isLoginSuccessful()) {
            // login successful
        } else {
            // check remediation options and continue the flow
        }
    }

    private void getTokenWithInteractionCode() throws ProcessingException {
        if (idxResponse.isLoginSuccessful()) {
            // exchange interaction code for token
            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);

            String accessToken = tokenResponse.getAccessToken();
            String idToken = tokenResponse.getIdToken();
            Integer expiresIn = tokenResponse.getExpiresIn();
            String scope = tokenResponse.getScope();
            String tokenType = tokenResponse.getTokenType();
        }
    }
}
