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
package com.okta.idx.sdk.api.wrapper;

import com.okta.commons.lang.Assert;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.AuthenticationOptions;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.ChangePasswordOptions;
import com.okta.idx.sdk.api.model.Credentials;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.RemediationType;
import com.okta.idx.sdk.api.request.AnswerChallengeRequest;
import com.okta.idx.sdk.api.request.AnswerChallengeRequestBuilder;
import com.okta.idx.sdk.api.request.IdentifyRequest;
import com.okta.idx.sdk.api.request.IdentifyRequestBuilder;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

public class AuthenticationWrapper {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationWrapper.class);

    /**
     * Authenticate user with the supplied Authentication options (username and password) and
     * returns the Authentication response object that contains:
     * - IDX Client context
     * - Token (access_token/id_token/refresh_token) object
     * - Authentication status
     * <p>
     * Note: This requires 'Password' as the ONLY required factor in app Sign-on policy configuration.
     *
     * @param client                the IDX Client
     * @param authenticationOptions the Authenticator options
     * @return the Authentication response
     */
    public static AuthenticationResponse authenticate(IDXClient client, AuthenticationOptions authenticationOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        TokenResponse tokenResponse;
        IDXClientContext idxClientContext;

        try {
            idxClientContext = client.interact();
            Assert.notNull(idxClientContext, "IDX client context may not be null");
            authenticationResponse.setIdxClientContext(idxClientContext);

            IDXResponse introspectResponse = client.introspect(idxClientContext);
            String stateHandle = introspectResponse.getStateHandle();
            Assert.hasText(stateHandle, "State handle may not be null");

            RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();
            printRemediationOptions(remediationOptions);

            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .filter(x -> RemediationType.IDENTIFY.equals(x.getName()))
                    .findFirst();
            Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation option " + RemediationType.IDENTIFY);
            RemediationOption remediationOption = remediationOptionsOptional.get();

            // Check if identify flow needs to include credentials
            boolean isIdentifyInOneStep = isRemediationRequireCredentials(RemediationType.IDENTIFY, introspectResponse);

            IdentifyRequest identifyRequest;

            if (isIdentifyInOneStep) {
                Credentials credentials = new Credentials();
                credentials.setPasscode(authenticationOptions.getPassword().toCharArray());

                identifyRequest = IdentifyRequestBuilder.builder()
                        .withIdentifier(authenticationOptions.getUsername())
                        .withCredentials(credentials)
                        .withStateHandle(stateHandle)
                        .build();
            } else {
                identifyRequest = IdentifyRequestBuilder.builder()
                        .withIdentifier(authenticationOptions.getUsername())
                        .withStateHandle(stateHandle)
                        .build();
            }

            // identify user
            IDXResponse identifyResponse = remediationOption.proceed(client, identifyRequest);

            if (isIdentifyInOneStep) {
                // we expect success
                if (!identifyResponse.isLoginSuccessful()) {
                    // verify if password expired
                    if (isRemediationRequireCredentials(RemediationType.REENROLL_AUTHENTICATOR, identifyResponse)) {
                        logger.warn("Password expired!");
                        authenticationResponse.setAuthenticationStatus(AuthenticationStatus.PASSWORD_EXPIRED);
                    } else {
                        logger.error("Unexpected remediation {}", RemediationType.REENROLL_AUTHENTICATOR);
                        Arrays.stream(identifyResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                        authenticationResponse.setAuthenticationStatus(AuthenticationStatus.FAILURE);
                    }
                } else {
                    // login successful
                    logger.info("Login Successful!");
                    tokenResponse = identifyResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                    authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                    authenticationResponse.setTokenResponse(tokenResponse);
                }
            } else {
                if (!isRemediationRequireCredentials(RemediationType.CHALLENGE_AUTHENTICATOR, identifyResponse)) {
                    logger.error("Unexpected remediation {}", RemediationType.CHALLENGE_AUTHENTICATOR);
                    Arrays.stream(identifyResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                    authenticationResponse.setAuthenticationStatus(AuthenticationStatus.FAILURE);
                } else {
                    remediationOptions = identifyResponse.remediation().remediationOptions();
                    printRemediationOptions(remediationOptions);

                    remediationOptionsOptional = Arrays.stream(remediationOptions)
                            .filter(x -> RemediationType.CHALLENGE_AUTHENTICATOR.equals(x.getName()))
                            .findFirst();
                    Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation option " + RemediationType.CHALLENGE_AUTHENTICATOR);

                    remediationOption = remediationOptionsOptional.get();

                    // answer password authenticator challenge
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(authenticationOptions.getPassword().toCharArray());

                    // build answer password authenticator challenge request
                    AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                            .withStateHandle(stateHandle)
                            .withCredentials(credentials)
                            .build();
                    IDXResponse challengeResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

                    if (!challengeResponse.isLoginSuccessful()) {
                        // verify if password expired
                        if (isRemediationRequireCredentials(RemediationType.REENROLL_AUTHENTICATOR, challengeResponse)) {
                            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.PASSWORD_EXPIRED);
                        } else {
                            logger.error("Unexpected remediation {}", RemediationType.REENROLL_AUTHENTICATOR);
                            Arrays.stream(challengeResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.FAILURE);
                        }
                    } else {
                        // login successful
                        logger.info("Login Successful!");
                        tokenResponse = challengeResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                        authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                        authenticationResponse.setTokenResponse(tokenResponse);
                    }
                }
            }
            return authenticationResponse;
        } catch (ProcessingException e) {
            List<String> errors = new LinkedList<>();
            Arrays.stream(e.getErrorResponse().getMessages().getValue()).forEach(msg -> errors.add(msg.getMessage()));
            logger.error("Something went wrong! {}, {}", e, errors);
            authenticationResponse.setErrors(errors);
            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.FAILURE);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.FAILURE);
        }

        return authenticationResponse;
    }

    public static AuthenticationResponse changePassword(IDXClient client, IDXClientContext idxClientContext, ChangePasswordOptions changePasswordOptions) {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        TokenResponse tokenResponse;

        try {
            // re-enter flow with context
            IDXResponse introspectResponse = client.introspect(idxClientContext);

            // verify if password expired
            if (!isRemediationRequireCredentials(RemediationType.REENROLL_AUTHENTICATOR, introspectResponse)) {
                logger.error("Unexpected remediation {}", RemediationType.REENROLL_AUTHENTICATOR);
            } else {

                RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();
                printRemediationOptions(remediationOptions);

                Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                        .filter(x -> RemediationType.REENROLL_AUTHENTICATOR.equals(x.getName()))
                        .findFirst();
                Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation option " + RemediationType.REENROLL_AUTHENTICATOR);
                RemediationOption remediationOption = remediationOptionsOptional.get();

                // set new password
                Credentials credentials = new Credentials();
                credentials.setPasscode(changePasswordOptions.getNewPassword().toCharArray());

                // build answer password authenticator challenge request
                AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                        .withStateHandle(introspectResponse.getStateHandle())
                        .withCredentials(credentials)
                        .build();

                IDXResponse resetPasswordResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

                if (resetPasswordResponse.isLoginSuccessful()) {
                    // login successful
                    logger.info("Login Successful!");
                    tokenResponse = resetPasswordResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                    authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                    authenticationResponse.setTokenResponse(tokenResponse);
                    return authenticationResponse;
                } else {
                    logger.error("Unexpected remediation {}", RemediationType.SUCCESS_WITH_INTERACTION_CODE);
                }
            }
        } catch (ProcessingException e) {
            List<String> errors = new LinkedList<>();
            Arrays.stream(e.getErrorResponse().getMessages().getValue()).forEach(msg -> errors.add(msg.getMessage()));
            logger.error("Something went wrong! {}, {}", e, errors);
            authenticationResponse.setErrors(errors);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
        }

        return authenticationResponse;
    }

    private static boolean isRemediationRequireCredentials(String remediationOptionName, IDXResponse idxResponse) {
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();

        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> remediationOptionName.equals(x.getName()))
                .findFirst();
        Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation option " + remediationOptionName);

        RemediationOption remediationOption = remediationOptionsOptional.get();
        FormValue[] formValues = remediationOption.form();

        Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                .filter(x -> "credentials".equals(x.getName()))
                .findFirst();

        return credentialsFormValueOptional.isPresent();
    }

    private static void printRemediationOptions(RemediationOption[] remediationOptions) {
        logger.info("Remediation Options: {}", Arrays.stream(remediationOptions)
                .map(RemediationOption::getName)
                .collect(Collectors.toList()));
    }
}
