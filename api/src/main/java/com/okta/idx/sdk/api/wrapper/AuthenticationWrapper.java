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
import com.okta.idx.sdk.api.model.Authenticator;
import com.okta.idx.sdk.api.model.ChangePasswordOptions;
import com.okta.idx.sdk.api.model.Credentials;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.RecoverPasswordOptions;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.RemediationType;
import com.okta.idx.sdk.api.model.VerifyAuthenticatorOptions;
import com.okta.idx.sdk.api.request.AnswerChallengeRequest;
import com.okta.idx.sdk.api.request.AnswerChallengeRequestBuilder;
import com.okta.idx.sdk.api.request.ChallengeRequest;
import com.okta.idx.sdk.api.request.ChallengeRequestBuilder;
import com.okta.idx.sdk.api.request.EnrollRequest;
import com.okta.idx.sdk.api.request.EnrollRequestBuilder;
import com.okta.idx.sdk.api.request.IdentifyRequest;
import com.okta.idx.sdk.api.request.IdentifyRequestBuilder;
import com.okta.idx.sdk.api.request.RecoverRequest;
import com.okta.idx.sdk.api.request.RecoverRequestBuilder;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.Map;
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

            RemediationOption remediationOption = extractRemediationOption(remediationOptions, RemediationType.IDENTIFY);

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
                        String errMsg = "Unexpected remediation: " + RemediationType.REENROLL_AUTHENTICATOR;
                        logger.error("{}", errMsg);
                        Arrays.stream(identifyResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                    }
                } else {
                    // login successful
                    logger.info("Login Successful!");
                    tokenResponse = identifyResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                    authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                    authenticationResponse.setTokenResponse(tokenResponse);
                }
            } else {
                if (identifyResponse.getMessages() != null) {
                    Arrays.stream(identifyResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                }
                else if (!isRemediationRequireCredentials(RemediationType.CHALLENGE_AUTHENTICATOR, identifyResponse)) {
                    String errMsg = "Unexpected remediation: " + RemediationType.CHALLENGE_AUTHENTICATOR;
                    logger.error("{}", errMsg);
                    Arrays.stream(identifyResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                } else {
                    remediationOptions = identifyResponse.remediation().remediationOptions();
                    printRemediationOptions(remediationOptions);

                    remediationOption = extractRemediationOption(remediationOptions, RemediationType.CHALLENGE_AUTHENTICATOR);

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
                            String errMsg = "Unexpected remediation: " + RemediationType.REENROLL_AUTHENTICATOR;
                            logger.error("{}", errMsg);
                            Arrays.stream(identifyResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
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
            Arrays.stream(e.getErrorResponse().getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
            logger.error("Something went wrong! {}, {}", e, authenticationResponse.getErrors());
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        return authenticationResponse;
    }

    public static AuthenticationResponse changePassword(IDXClient client, IDXClientContext idxClientContext, ChangePasswordOptions changePasswordOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setIdxClientContext(idxClientContext);
        TokenResponse tokenResponse;

        try {
            // re-enter flow with context
            IDXResponse introspectResponse = client.introspect(idxClientContext);

            // check if flow is password expiration or forgot password
            RemediationOption[] resetAuthenticatorRemediationOptions = introspectResponse.remediation().remediationOptions();
            printRemediationOptions(resetAuthenticatorRemediationOptions);

            RemediationOption resetAuthenticatorRemediationOption =
                    extractRemediationOption(resetAuthenticatorRemediationOptions, RemediationType.RESET_AUTHENTICATOR);

            // set new password
            Credentials credentials = new Credentials();
            credentials.setPasscode(changePasswordOptions.getNewPassword().toCharArray());

            // build answer password authenticator challenge request
            AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                    .withStateHandle(introspectResponse.getStateHandle())
                    .withCredentials(credentials)
                    .build();

            IDXResponse resetPasswordResponse = resetAuthenticatorRemediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

            if (resetPasswordResponse.isLoginSuccessful()) {
                // login successful
                logger.info("Login Successful!");
                tokenResponse = resetPasswordResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                authenticationResponse.setTokenResponse(tokenResponse);
                return authenticationResponse;
            } else {
                String errMsg = "Unexpected remediation: " + RemediationType.SUCCESS_WITH_INTERACTION_CODE;
                logger.error("{}", errMsg);
                Arrays.stream(resetPasswordResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
            }
        } catch (ProcessingException e) {
            Arrays.stream(e.getErrorResponse().getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
            logger.error("Something went wrong! {}, {}", e, authenticationResponse.getErrors());
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        return authenticationResponse;
    }

    /**
     * Recover Password with the supplied authenticator options.
     *
     * @param client the IDX Client
     * @param recoverPasswordOptions the password recovery options
     * @return the Authentication response
     */
    public static AuthenticationResponse recoverPassword(IDXClient client, RecoverPasswordOptions recoverPasswordOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
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

            RemediationOption remediationOption = extractRemediationOption(remediationOptions, RemediationType.IDENTIFY);

            IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
                        .withIdentifier(recoverPasswordOptions.getUsername())
                        .withStateHandle(stateHandle)
                        .build();

            // identify user
            IDXResponse identifyResponse = remediationOption.proceed(client, identifyRequest);

            remediationOptions = identifyResponse.remediation().remediationOptions();
            printRemediationOptions(remediationOptions);

            if (identifyResponse.getCurrentAuthenticatorEnrollment() == null ||
                identifyResponse.getCurrentAuthenticatorEnrollment().getValue() == null ||
                identifyResponse.getCurrentAuthenticatorEnrollment().getValue().getRecover() == null) {
                  Arrays.stream(identifyResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                } else {

            // recover password
            RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
                    .withStateHandle(identifyResponse.getStateHandle())
                    .build();

            IDXResponse recoverResponse = identifyResponse.getCurrentAuthenticatorEnrollment().getValue().getRecover()
                    .proceed(client, recoverRequest);

            RemediationOption[] recoverResponseRemediationOptions = recoverResponse.remediation().remediationOptions();
            RemediationOption selectAuthenticatorAuthenticateRemediationOption = extractRemediationOption(recoverResponseRemediationOptions, RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE);

            Map<String, String> authenticatorOptions = selectAuthenticatorAuthenticateRemediationOption.getAuthenticatorOptions();

            Authenticator authenticator = new Authenticator();

            authenticator.setId(authenticatorOptions.get(recoverPasswordOptions.getAuthenticatorType().toString()));

            ChallengeRequest selectAuthenticatorRequest = ChallengeRequestBuilder.builder()
                    .withStateHandle(stateHandle)
                    .withAuthenticator(authenticator)
                    .build();

            IDXResponse selectAuthenticatorResponse = selectAuthenticatorAuthenticateRemediationOption.proceed(client, selectAuthenticatorRequest);

            RemediationOption[] selectAuthenticatorResponseRemediationOptions = selectAuthenticatorResponse.remediation().remediationOptions();

            RemediationOption challengeAuthenticatorRemediationOption =
                    extractRemediationOption(selectAuthenticatorResponseRemediationOptions, RemediationType.CHALLENGE_AUTHENTICATOR);

            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION);
          }
        } catch (ProcessingException e) {
            Arrays.stream(e.getErrorResponse().getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
            logger.error("Something went wrong! {}, {}", e, authenticationResponse.getErrors());
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        return authenticationResponse;
    }

    /**
     * Verify Authenticator with the supplied authenticator options.
     *
     * @param client                the IDX Client
     * @param idxClientContext      the IDX Client context
     * @param verifyAuthenticatorOptions the verify Authenticator options
     * @return the Authentication response
     */
    public static AuthenticationResponse verifyAuthenticator(IDXClient client, IDXClientContext idxClientContext, VerifyAuthenticatorOptions verifyAuthenticatorOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setIdxClientContext(idxClientContext);

        try {
            // re-enter flow with context
            IDXResponse introspectResponse = client.introspect(idxClientContext);

            // verify if password expired
            if (!isRemediationRequireCredentials(RemediationType.CHALLENGE_AUTHENTICATOR, introspectResponse)) {
                String errMsg = "Unexpected remediation: " + RemediationType.CHALLENGE_AUTHENTICATOR;
                logger.error("{}", errMsg);
            } else {

                Credentials credentials = new Credentials();
                credentials.setPasscode(verifyAuthenticatorOptions.getCode().toCharArray());

                // build answer password authenticator challenge request
                AnswerChallengeRequest challengeAuthenticatorRequest = AnswerChallengeRequestBuilder.builder()
                        .withStateHandle(introspectResponse.getStateHandle())
                        .withCredentials(credentials)
                        .build();

                RemediationOption[] introspectRemediationOptions = introspectResponse.remediation().remediationOptions();
                printRemediationOptions(introspectRemediationOptions);

                RemediationOption challengeAuthenticatorRemediationOption =
                        extractRemediationOption(introspectRemediationOptions, RemediationType.CHALLENGE_AUTHENTICATOR);

                IDXResponse challengeAuthenticatorResponse =
                        challengeAuthenticatorRemediationOption.proceed(client, challengeAuthenticatorRequest);

                RemediationOption[] challengeAuthenticatorResponseRemediationOptions =
                        challengeAuthenticatorResponse.remediation().remediationOptions();
                printRemediationOptions(challengeAuthenticatorResponseRemediationOptions);

                RemediationOption resetAuthenticatorRemediationOption =
                        extractRemediationOption(challengeAuthenticatorResponseRemediationOptions, RemediationType.RESET_AUTHENTICATOR);

                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_PASSWORD_RESET);
            }
        } catch (ProcessingException e) {
          logger.error("Error occurred", e);
            Arrays.stream(e.getErrorResponse().getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
            logger.error("Something went wrong! {}, {}", e, authenticationResponse.getErrors());
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        return authenticationResponse;
    }

    /**
     * Register a new user.
     *
     * @param client                the IDX Client
     * @param username              the login email
     * @return the Authentication response
     */
    public static AuthenticationResponse register(IDXClient client, String username) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            IDXClientContext idxClientContext = client.interact();
            Assert.notNull(idxClientContext, "IDX client context may not be null");
            authenticationResponse.setIdxClientContext(idxClientContext);

            IDXResponse introspectResponse = client.introspect(idxClientContext);
            String stateHandle = introspectResponse.getStateHandle();
            Assert.hasText(stateHandle, "State handle may not be null");

            RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();
            printRemediationOptions(remediationOptions);

            RemediationOption selectEnrollProfileRemediationOption =
                    extractRemediationOption(remediationOptions, RemediationType.SELECT_ENROLL_PROFILE);

            EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                    .withStateHandle(stateHandle)
                    .build();

            // enroll new user
            IDXResponse enrollResponse = selectEnrollProfileRemediationOption.proceed(client, enrollRequest);

            //TODO


        } catch (ProcessingException e) {
            Arrays.stream(e.getErrorResponse().getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
            logger.error("Something went wrong! {}, {}", e, authenticationResponse.getErrors());
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
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

    private static RemediationOption extractRemediationOption(RemediationOption[] remediationOptions, String remediationType) {
        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> remediationType.equals(x.getName()))
                .findFirst();
        Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation option " + remediationType);
        return remediationOptionsOptional.get();
    }

    private static void printRemediationOptions(RemediationOption[] remediationOptions) {
        logger.info("Remediation Options: {}", Arrays.stream(remediationOptions)
                .map(RemediationOption::getName)
                .collect(Collectors.toList()));
    }
}
