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
import com.okta.sdk.api.response.IDXResponse;
import com.okta.sdk.api.response.InteractResponse;
import com.okta.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Map;
import java.util.Optional;
import java.util.Scanner;

/**
 * This class demonstrates the SDK usage to help get started.
 */
public class Quickstart {

    private static final Logger log = LoggerFactory.getLogger(Quickstart.class);

    private static final IDXClient client = Clients.builder().build();

    private static final String IDENTIFIER = "someone@example.com";             // replace
    private static final char[] PASSWORD = {'p','a','s','s','w','o','r','d'};   // replace
    private static final char[] SECURITY_QUESTION_ANSWER = { 'c','a','t'};      // replace

    public static void main(String... args) throws JsonProcessingException {

        /**
         * Any of the below flows could be run depending on how the Authenticators are setup in your org.
         */

        // complete login flow with Password & Email Authenticators
        runLoginFlowWithPasswordAndEmailAuthenticators();

        // complete login flow with Security question & Email Authenticators
        runLoginFlowWithSecurityQnAndEmailAuthenticators();
    }

    private static void runLoginFlowWithPasswordAndEmailAuthenticators() throws JsonProcessingException {

        try {
            // get interactionHandle
            InteractResponse interactResponse = client.interact();
            String interactHandle = interactResponse.getInteractionHandle();

            // exchange interactHandle for stateHandle
            IDXResponse idxResponse = client.introspect(Optional.of(interactHandle));
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
                    credentials.setPasscode(PASSWORD);

                    idxResponse = client.identify(IdentifyRequestBuilder.builder()
                            .withIdentifier(IDENTIFIER)
                            .withCredentials(credentials)
                            .withStateHandle(stateHandle)
                            .build());
                }
            } else {
                // credentials are not necessary; so sending just the identifier
                idxResponse = client.identify(IdentifyRequestBuilder.builder()
                        .withIdentifier(IDENTIFIER)
                        .withStateHandle(stateHandle)
                        .build());
            }

            // check if we landed success on login
            if (idxResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);
                log.info("Token: {}", tokenResponse);
            } else {
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
                credentials.setPasscode(PASSWORD);

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
                    credentials.setPasscode(emailPasscode.toCharArray());

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
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }

    private static void runLoginFlowWithSecurityQnAndEmailAuthenticators() throws JsonProcessingException {

        try {
            // get interactionHandle
            InteractResponse interactResponse = client.interact();
            String interactHandle = interactResponse.getInteractionHandle();

            // exchange interactHandle for stateHandle
            IDXResponse idxResponse = client.introspect(Optional.of(interactHandle));
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
                    credentials.setPasscode(PASSWORD);

                    idxResponse = client.identify(IdentifyRequestBuilder.builder()
                            .withIdentifier(IDENTIFIER)
                            .withCredentials(credentials)
                            .withStateHandle(stateHandle)
                            .build());
                }
            } else {
                // credentials are not necessary; so sending just the identifier
                idxResponse = client.identify(IdentifyRequestBuilder.builder()
                        .withIdentifier(IDENTIFIER)
                        .withStateHandle(stateHandle)
                        .build());
            }

            // check if we landed success on login
            if (idxResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client);
                log.info("Token: {}", tokenResponse);
            } else {
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

                // select security question authenticator
                Authenticator secQnAuthenticator = new Authenticator();
                secQnAuthenticator.setId(authenticatorOptions.get("security_question"));
                secQnAuthenticator.setMethodType("security_question");

                // build security question authenticator challenge request
                ChallengeRequest secQnAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                        .withAuthenticator(secQnAuthenticator)
                        .withStateHandle(stateHandle)
                        .build();
                idxResponse = remediationOption.proceed(client, secQnAuthenticatorChallengeRequest);

                // check remediation options to continue the flow
                remediationOptions = idxResponse.remediation().remediationOptions();
                remediationOptionsOptional = Arrays.stream(remediationOptions)
                        .filter(x -> "challenge-authenticator".equals(x.getName()))
                        .findFirst();
                remediationOption = remediationOptionsOptional.get();

                // answer security question authenticator challenge
                Credentials credentials = new Credentials();
                credentials.setAnswer(SECURITY_QUESTION_ANSWER);

                // build answer password authenticator challenge request
                AnswerChallengeRequest secQnAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                        .withStateHandle(stateHandle)
                        .withCredentials(credentials)
                        .build();
                idxResponse = remediationOption.proceed(client, secQnAuthenticatorAnswerChallengeRequest);

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
                    credentials.setPasscode(emailPasscode.toCharArray());

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
        } catch (ProcessingException e) {
            log.error("Something went wrong! {}, {}", e.getMessage(), e.getErrorResponse().raw());
        }
    }
}
