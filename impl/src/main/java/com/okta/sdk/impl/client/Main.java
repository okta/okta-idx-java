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
package com.okta.sdk.impl.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.okta.sdk.api.client.Clients;
import com.okta.sdk.api.client.OktaIdentityEngineClient;
import com.okta.sdk.api.exception.ProcessingException;
import com.okta.sdk.api.model.Authenticator;
import com.okta.sdk.api.model.Credentials;
import com.okta.sdk.api.model.FormValue;
import com.okta.sdk.api.model.RemediationOption;
import com.okta.sdk.api.response.TokenResponse;
import com.okta.sdk.api.request.AnswerChallengeRequest;
import com.okta.sdk.api.request.AnswerChallengeRequestBuilder;
import com.okta.sdk.api.request.ChallengeRequest;
import com.okta.sdk.api.request.ChallengeRequestBuilder;
import com.okta.sdk.api.request.IdentifyRequestBuilder;
import com.okta.sdk.api.response.OktaIdentityEngineResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Optional;
import java.util.Scanner;
import java.util.Set;

/**
 * This is for testing purpose ONLY.
 *
 * TODO: DO NOT CHECK-IN THIS FILE!
 */
public class Main {

    private static final Logger log = LoggerFactory.getLogger(BaseOktaIdentityEngineClient.class);

    /* trexcloud org */
//    private static final String ISSUER = "https://idx-devex.trexcloud.com";
//    private static final String CLIENT_ID = "0oa3jxy2kpqZs9fOU0g7";
//    private static final String CLIENT_SECRET = "6NMR5HuSlZ8LOM5X7jHqE9Up9xLOqoHA7NGymjPo";
//    private static final String IDENTIFIER = "arvind.krishnakumar@okta.com";

    /* devex-idx-testing oktapreview org */
    private static final String ISSUER = "https://devex-idx-testing.oktapreview.com";
    private static final String CLIENT_ID = "0oa2ilb4mR2PZeL8p1d6";
    private static final String CLIENT_SECRET = "08Fqmq4gy77Tq67EOPkc8ZVr4ZGGADbzBj_zpVwm";
    private static final String IDENTIFIER = "arvind.mercedes@gmail.com";

    /* devex-idx-ct6.clouditude.com */
//    private static final String ISSUER = "https://devex-idx-ct6.clouditude.com";
//    private static final String CLIENT_ID = "";
//    private static final String CLIENT_SECRET = "";
//    private static final String IDENTIFIER = "arvind.mercedes@gmail.com";

    private static final String PASSWORD = "Sclass15683!";
    private static final Set<String> SCOPE = new HashSet<>(Arrays.asList("openid", "profile"));

    public static void main(String... args) throws ProcessingException, JsonProcessingException {

//        OktaIdentityEngineClient client = Clients.builder()
//            .setIssuer(ISSUER)
//            .setClientId(CLIENT_ID)
//            .setClientSecret(CLIENT_SECRET)
//            .setScopes(SCOPE)
//            .build();

        OktaIdentityEngineClient client = Clients.builder().build();

        OktaIdentityEngineResponse oktaIdentityEngineResponse = client.start(Optional.empty());

        String stateHandle = oktaIdentityEngineResponse.getStateHandle();

        RemediationOption[] remediationOptions = oktaIdentityEngineResponse.remediation().remediationOptions();
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
            .findFirst();
        RemediationOption remediationOption = remediationOptionsOptional.get();
        FormValue[] formValues = remediationOption.form();

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

                oktaIdentityEngineResponse = client.identify(IdentifyRequestBuilder.builder()
                    .withIdentifier(IDENTIFIER)
                    .withCredentials(credentials)
                    .withStateHandle(stateHandle)
                    .build());
            }
        } else {
            oktaIdentityEngineResponse = client.identify(IdentifyRequestBuilder.builder()
                .withIdentifier(IDENTIFIER)
                .withStateHandle(stateHandle)
                .build());
        }

        if (oktaIdentityEngineResponse.isLoginSuccessful()) {
            log.info("Login Successful!");
            TokenResponse tokenResponse = oktaIdentityEngineResponse.getSuccessWithInteractionCode().exchangeCode(client);
            log.info("Token: {}", tokenResponse);
        }
        else {
            log.info("Login not successful yet!: {}", oktaIdentityEngineResponse.raw());

            // get remediation options to go to the next step
            remediationOptions = oktaIdentityEngineResponse.remediation().remediationOptions();
            remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                .findFirst();
            remediationOption = remediationOptionsOptional.get();

            // get authenticator options
            Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
            log.info("Authenticator Options: {}", authenticatorOptions);

            // pick password authenticator
            Authenticator passwordAuthenticator = new Authenticator();
            passwordAuthenticator.setId(authenticatorOptions.get("password"));
            passwordAuthenticator.setMethodType("password");

            ChallengeRequest passwordAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                .withAuthenticator(passwordAuthenticator)
                .withStateHandle(stateHandle)
                .build();
            oktaIdentityEngineResponse = remediationOption.proceed(client, passwordAuthenticatorChallengeRequest);

            remediationOptions = oktaIdentityEngineResponse.remediation().remediationOptions();
            remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> "challenge-authenticator".equals(x.getName()))
                .findFirst();
            remediationOption = remediationOptionsOptional.get();

            // answer password authenticator challenge
            Credentials credentials = new Credentials();
            credentials.setPasscode(PASSWORD);

            AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                .withStateHandle(stateHandle)
                .withCredentials(credentials)
                .build();
            oktaIdentityEngineResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

            if (oktaIdentityEngineResponse.isLoginSuccessful()) {
                log.info("Login Successful!");
                log.info("Exchanged interaction code for token {}",
                    oktaIdentityEngineResponse.getSuccessWithInteractionCode().exchangeCode(client));
            } else {
                log.info("Login not successful yet!: {}", oktaIdentityEngineResponse.raw());

                // get remediation options to go to the next step
                remediationOptions = oktaIdentityEngineResponse.remediation().remediationOptions();
                remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                    .findFirst();
                remediationOption = remediationOptionsOptional.get();

                // get authenticator options
                authenticatorOptions = remediationOption.getAuthenticatorOptions();
                log.info("Authenticator Options: {}", authenticatorOptions);

                // pick email authenticator
                Authenticator emailAuthenticator = new Authenticator();
                emailAuthenticator.setId(authenticatorOptions.get("email"));
                emailAuthenticator.setMethodType("email");

                ChallengeRequest emailAuthenticatorChallengeRequest = ChallengeRequestBuilder.builder()
                    .withAuthenticator(emailAuthenticator)
                    .withStateHandle(stateHandle)
                    .build();
                oktaIdentityEngineResponse = remediationOption.proceed(client, emailAuthenticatorChallengeRequest);

                // answer email authenticator challenge
                remediationOptions = oktaIdentityEngineResponse.remediation().remediationOptions();
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

                AnswerChallengeRequest emailAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                    .withStateHandle(stateHandle)
                    .withCredentials(credentials)
                    .build();
                oktaIdentityEngineResponse = remediationOption.proceed(client, emailAuthenticatorAnswerChallengeRequest);

                if (oktaIdentityEngineResponse.isLoginSuccessful()) {
                    log.info("Login Successful!");
                    log.info("Exchanged interaction code for token {}",
                        oktaIdentityEngineResponse.getSuccessWithInteractionCode().exchangeCode(client));
                }
            }
        }
    }
}
