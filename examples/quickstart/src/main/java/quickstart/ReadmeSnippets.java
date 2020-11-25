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
import com.okta.sdk.api.request.IdentifyRequestBuilder;
import com.okta.sdk.api.response.InteractResponse;
import com.okta.sdk.api.response.IDXResponse;
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

    public static void main(String... args) throws ProcessingException, JsonProcessingException {

        // build the client
        IDXClient client = Clients.builder()
            .setIssuer("{issuer}")
            .setClientId("{clientId}")
            .setClientSecret("{clientSecret}")
            .setScopes(new HashSet<>(Arrays.asList("{scope-1}", "{scope-2}")))
            .build();

        // get interactionHandle
        InteractResponse interactResponse = client.interact(Optional.empty());
        String interactHandle = interactResponse.getInteractionHandle();

        // exchange interactHandle for stateHandle
        IDXResponse idxResponse = client.introspect(interactHandle);
        String stateHandle = idxResponse.getStateHandle();

        // check remediation options to continue the flow
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
            .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();
        FormValue[] formValues = remediationOption.form();

        // check of credentials are required to move on to next step
        Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
            .filter(x -> "credentials".equals(x.getName()))
            .findFirst();

        if (credentialsFormValueOptional.isPresent()) {
            FormValue credentialsFormValue = credentialsFormValueOptional.get();

            // check if credentials are required to be sent in identify API
            if (credentialsFormValue.isRequired()) {
                log.info("Credentials are REQUIRED to be sent in identify request (next step)");
                Credentials credentials = new Credentials();
                credentials.setPasscode("{password}");

                idxResponse = client.identify(IdentifyRequestBuilder.builder()
                    .withIdentifier("{identifier}") // email
                    .withCredentials(credentials)
                    .withStateHandle(stateHandle)
                    .build());
            }
        } else {
            // credentials are not necessary; so sending just the identifier
            idxResponse = client.identify(IdentifyRequestBuilder.builder()
                .withIdentifier("{identifier}")
                .withStateHandle(stateHandle)
                .build());
        }

        // check if we landed success on login
        if (idxResponse.isLoginSuccessful()) {
            log.info("Login Successful!");
            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);
            log.info("Token: {}", tokenResponse);
        }
        else {
            // logon is not successful yet; we need to follow more remediation steps.
            log.info("Login not successful yet!: {}", idxResponse.raw());

            // get remediation options to go to the next step
            remediationOptions = idxResponse.remediation().remediationOptions();
            remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                .findFirst();
            remediationOption = remediationOptionsOptional.get();

            // get authenticator options
            Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
            log.info("Authenticator Options: {}", authenticatorOptions);

            // select password authenticator
            Authenticator passwordAuthenticator = new Authenticator();
            passwordAuthenticator.setId(authenticatorOptions.get("password"));
            passwordAuthenticator.setMethodType("password");

            // build password authenticator challenge request
            ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                .withAuthenticator(passwordAuthenticator)
                .withStateHandle(stateHandle)
                .build();
            idxResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest);

            // check remediation options to continue the flow
            remediationOptions = idxResponse.remediation().remediationOptions();
            remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "challenge-authenticator".equals(x.getName()))
                .findFirst();
            remediationOption = remediationOptionsOptional.get();

            // answer password authenticator challenge
            Credentials credentials = new Credentials();
            credentials.setPasscode("{password}"); // password associated with your email identifier

            // build answer password authenticator challenge request
            AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                .withStateHandle(stateHandle)
                .withCredentials(credentials)
                .build();
            idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

            // check if we landed success on login
            if (idxResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                log.info("Exchanged interaction code for token {}",
                    idxResponse.getSuccessWithInteractionCode().exchangeCode(client));
            } else {
                // logon is not successful yet; we need to follow more remediation steps.
                log.info("Login not successful yet!: {}", idxResponse.raw());

                // check remediation options to continue the flow
                remediationOptions = idxResponse.remediation().remediationOptions();
                remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                    .findFirst();
                remediationOption = remediationOptionsOptional.get();

                // get authenticator options
                authenticatorOptions = remediationOption.getAuthenticatorOptions();
                log.info("Authenticator Options: {}", authenticatorOptions);

                // select email authenticator
                Authenticator emailAuthenticator = new Authenticator();
                emailAuthenticator.setId(authenticatorOptions.get("email"));
                emailAuthenticator.setMethodType("email");

                // build email authenticator challenge request
                ChallengeRequest emailAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                    .withAuthenticator(emailAuthenticator)
                    .withStateHandle(stateHandle)
                    .build();
                idxResponse = remediationOption.proceed(client, emailAuthenticatorChallengeRequest);

                // answer email authenticator challenge
                remediationOptions = idxResponse.remediation().remediationOptions();
                remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .filter(x -> "challenge-authenticator".equals(x.getName()))
                    .findFirst();
                remediationOption = remediationOptionsOptional.get();

                // enter passcode received in email
                Scanner in = new Scanner(System.in, "UTF-8");
                log.info("Enter Email Passcode: ");
                String emailPasscode = in.nextLine();

                credentials = new Credentials();
                credentials.setPasscode(emailPasscode);

                // build answer email authenticator challenge request
                AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                    .withStateHandle(stateHandle)
                    .withCredentials(credentials)
                    .build();
                idxResponse = remediationOption.proceed(client, emailAuthenticatorAnswerChallengeRequest);

                // check if we landed success on login
                if (idxResponse.isLoginSuccessful()) {
                    log.info("Login Successful!");
                    // exchange the received interaction code for a token
                    log.info("Exchanged interaction code for token {}",
                        idxResponse.getSuccessWithInteractionCode().exchangeCode(client));
                }
            }
        }
    }
}

