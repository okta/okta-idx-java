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
package com.okta.idx.sdk.api.wrapper;

import com.okta.commons.lang.Assert;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.AuthenticationOptions;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.Authenticator;
import com.okta.idx.sdk.api.model.AuthenticatorType;
import com.okta.idx.sdk.api.model.AuthenticatorUIOption;
import com.okta.idx.sdk.api.model.ChangePasswordOptions;
import com.okta.idx.sdk.api.model.Credentials;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.RecoverPasswordOptions;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.RemediationType;
import com.okta.idx.sdk.api.model.UserProfile;
import com.okta.idx.sdk.api.model.VerifyAuthenticatorOptions;
import com.okta.idx.sdk.api.request.AnswerChallengeRequest;
import com.okta.idx.sdk.api.request.AnswerChallengeRequestBuilder;
import com.okta.idx.sdk.api.request.ChallengeRequest;
import com.okta.idx.sdk.api.request.ChallengeRequestBuilder;
import com.okta.idx.sdk.api.request.EnrollRequest;
import com.okta.idx.sdk.api.request.EnrollRequestBuilder;
import com.okta.idx.sdk.api.request.EnrollUserProfileUpdateRequest;
import com.okta.idx.sdk.api.request.EnrollUserProfileUpdateRequestBuilder;
import com.okta.idx.sdk.api.request.IdentifyRequest;
import com.okta.idx.sdk.api.request.IdentifyRequestBuilder;
import com.okta.idx.sdk.api.request.RecoverRequest;
import com.okta.idx.sdk.api.request.RecoverRequestBuilder;
import com.okta.idx.sdk.api.request.SkipAuthenticatorEnrollmentRequest;
import com.okta.idx.sdk.api.request.SkipAuthenticatorEnrollmentRequestBuilder;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.ErrorResponse;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.NewUserRegistrationResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
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
    public static AuthenticationResponse authenticate(IDXClient client,
                                                      AuthenticationOptions authenticationOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        TokenResponse tokenResponse;
        IDXClientContext idxClientContext = null;

        try {
            idxClientContext = client.interact();
            Assert.notNull(idxClientContext, "IDX client context may not be null");

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
                        Arrays.stream(identifyResponse.getMessages().getValue())
                                .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
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
                    Arrays.stream(identifyResponse.getMessages().getValue())
                            .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                }
                else if (!isRemediationRequireCredentials(RemediationType.CHALLENGE_AUTHENTICATOR, identifyResponse)) {
                    String errMsg = "Unexpected remediation: " + RemediationType.CHALLENGE_AUTHENTICATOR;
                    logger.error("{}", errMsg);
                    Arrays.stream(identifyResponse.getMessages().getValue())
                            .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                } else {
                    remediationOptions = identifyResponse.remediation().remediationOptions();
                    printRemediationOptions(remediationOptions);

                    remediationOption = extractRemediationOption(remediationOptions, RemediationType.CHALLENGE_AUTHENTICATOR);

                    // answer password authenticator challenge
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(authenticationOptions.getPassword().toCharArray());

                    // build answer password authenticator challenge request
                    AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest =
                            AnswerChallengeRequestBuilder.builder()
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
                            Arrays.stream(identifyResponse.getMessages().getValue())
                                    .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
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
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        authenticationResponse.setIdxClientContext(idxClientContext);
        return authenticationResponse;
    }

    /**
     * Change password with the supplied change password options reference.
     *
     * @param client                the IDX Client
     * @param idxClientContext      the IDC Client context
     * @return the Authentication response
     */
    public static AuthenticationResponse changePassword(IDXClient client,
                                                        IDXClientContext idxClientContext,
                                                        ChangePasswordOptions changePasswordOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
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
            AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest =
                    AnswerChallengeRequestBuilder.builder()
                    .withStateHandle(introspectResponse.getStateHandle())
                    .withCredentials(credentials)
                    .build();

            IDXResponse resetPasswordResponse =
                    resetAuthenticatorRemediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

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
                Arrays.stream(resetPasswordResponse.getMessages().getValue())
                        .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
            }
        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        authenticationResponse.setIdxClientContext(idxClientContext);
        return authenticationResponse;
    }

    /**
     * Recover Password with the supplied authenticator options.
     *
     * @param client the IDX Client
     * @param recoverPasswordOptions the password recovery options
     * @return the Authentication response
     */
    public static AuthenticationResponse recoverPassword(IDXClient client,
                                                         RecoverPasswordOptions recoverPasswordOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        IDXClientContext idxClientContext = null;

        try {
            idxClientContext = client.interact();
            Assert.notNull(idxClientContext, "IDX client context may not be null");

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
                  Arrays.stream(identifyResponse.getMessages().getValue())
                          .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                } else {

            // recover password
            RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
                    .withStateHandle(identifyResponse.getStateHandle())
                    .build();

            IDXResponse recoverResponse = identifyResponse.getCurrentAuthenticatorEnrollment().getValue().getRecover()
                    .proceed(client, recoverRequest);

            RemediationOption[] recoverResponseRemediationOptions = recoverResponse.remediation().remediationOptions();
            RemediationOption selectAuthenticatorAuthenticateRemediationOption =
                    extractRemediationOption(recoverResponseRemediationOptions, RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE);

            Map<String, String> authenticatorOptions =
                    selectAuthenticatorAuthenticateRemediationOption.getAuthenticatorOptions();

            Authenticator authenticator = new Authenticator();

            authenticator.setId(authenticatorOptions.get(recoverPasswordOptions.getAuthenticatorType().toString()));

            ChallengeRequest selectAuthenticatorRequest = ChallengeRequestBuilder.builder()
                    .withStateHandle(stateHandle)
                    .withAuthenticator(authenticator)
                    .build();

            IDXResponse selectAuthenticatorResponse =
                    selectAuthenticatorAuthenticateRemediationOption.proceed(client, selectAuthenticatorRequest);

            RemediationOption[] selectAuthenticatorResponseRemediationOptions =
                    selectAuthenticatorResponse.remediation().remediationOptions();

            extractRemediationOption(selectAuthenticatorResponseRemediationOptions, RemediationType.CHALLENGE_AUTHENTICATOR);

            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION);
          }
        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        authenticationResponse.setIdxClientContext(idxClientContext);
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
    public static AuthenticationResponse verifyAuthenticator(IDXClient client,
                                                             IDXClientContext idxClientContext,
                                                             VerifyAuthenticatorOptions verifyAuthenticatorOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

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

                extractRemediationOption(challengeAuthenticatorResponseRemediationOptions, RemediationType.RESET_AUTHENTICATOR);

                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_PASSWORD_RESET);
            }
        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        authenticationResponse.setIdxClientContext(idxClientContext);
        return authenticationResponse;
    }

    /**
     * Populate UI form values for signing up a new user.
     *
     * @param client                the IDX Client
     * @return the new user registration response
     */
    public static NewUserRegistrationResponse fetchSignUpFormValues(IDXClient client) {

        IDXClientContext idxClientContext = null;
        List<FormValue> enrollProfileFormValues;

        NewUserRegistrationResponse newUserRegistrationResponse = new NewUserRegistrationResponse();

        try {
            idxClientContext = client.interact();
            Assert.notNull(idxClientContext, "IDX client context may not be null");

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

            RemediationOption[] enrollRemediationOptions = enrollResponse.remediation().remediationOptions();
            printRemediationOptions(enrollRemediationOptions);

            RemediationOption enrollProfileRemediationOption =
                    extractRemediationOption(enrollRemediationOptions, RemediationType.ENROLL_PROFILE);

            enrollProfileFormValues = Arrays.stream(enrollProfileRemediationOption.form())
                    .filter(x-> "userProfile".equals(x.getName()))
                    .collect(Collectors.toList());

            newUserRegistrationResponse.setFormValues(enrollProfileFormValues);

        } catch (ProcessingException e) {
            handleProcessingException(e, newUserRegistrationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            newUserRegistrationResponse.addError(e.getMessage());
        }

        newUserRegistrationResponse.setIdxClientContext(idxClientContext);
        return newUserRegistrationResponse;
    }

    /**
     * Register new user with the supplied user profile reference.
     *
     * @param client                the IDX Client
     * @param idxClientContext      the IDC Client context
     * @param userProfile           the user profile
     * @return the Authentication response
     */
    public static AuthenticationResponse register(IDXClient client,
                                                  IDXClientContext idxClientContext,
                                                  UserProfile userProfile) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            IDXResponse introspectResponse = client.introspect(idxClientContext);
            String stateHandle = introspectResponse.getStateHandle();

            RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();
            printRemediationOptions(remediationOptions);

            RemediationOption remediationOption =
                    extractRemediationOption(remediationOptions, RemediationType.ENROLL_PROFILE);

            EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest =
                    EnrollUserProfileUpdateRequestBuilder.builder()
                    .withUserProfile(userProfile)
                    .withStateHandle(stateHandle)
                    .build();
            IDXResponse idxResponse = remediationOption.proceed(client, enrollUserProfileUpdateRequest);

            remediationOptions = idxResponse.remediation().remediationOptions();
            printRemediationOptions(remediationOptions);

            extractRemediationOption(remediationOptions, RemediationType.SELECT_AUTHENTICATOR_ENROLL);

        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        authenticationResponse.setIdxClientContext(idxClientContext);
        return authenticationResponse;
    }

    /**
     * Enroll authenticator of the supplied type.
     *
     * @param client                the IDX Client
     * @param idxClientContext      the IDC Client context
     * @param authenticatorType     the authenticator type
     * @return the Authentication response
     */
    public static AuthenticationResponse enrollAuthenticator(IDXClient client,
                                                             IDXClientContext idxClientContext,
                                                             String authenticatorType) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            IDXResponse introspectResponse = client.introspect(idxClientContext);
            String stateHandle = introspectResponse.getStateHandle();

            RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();
            printRemediationOptions(remediationOptions);

            RemediationOption remediationOption =
                    extractRemediationOption(remediationOptions, RemediationType.SELECT_AUTHENTICATOR_ENROLL);

            Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
            logger.info("Authenticator Options: {}", authenticatorOptions);

            Authenticator authenticator = new Authenticator();

            if (authenticatorType.equals(AuthenticatorType.EMAIL.toString())) {
                authenticator.setId(authenticatorOptions.get(AuthenticatorType.EMAIL.toString()));
                authenticator.setMethodType(AuthenticatorType.EMAIL.toString());
            } else if (authenticatorType.equals(AuthenticatorType.PASSWORD.toString())) {
                authenticator.setId(authenticatorOptions.get(AuthenticatorType.PASSWORD.toString()));
                authenticator.setMethodType(AuthenticatorType.PASSWORD.toString());
            } else {
                String errMsg = "Unsupported authenticator " + authenticatorType;
                logger.error(errMsg);
                throw new IllegalArgumentException(errMsg);
            }

            EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                    .withAuthenticator(authenticator)
                    .withStateHandle(stateHandle)
                    .build();

            IDXResponse idxResponse = remediationOption.proceed(client, enrollRequest);

            RemediationOption[] enrollRemediationOptions = idxResponse.remediation().remediationOptions();
            printRemediationOptions(enrollRemediationOptions);

            extractRemediationOption(enrollRemediationOptions, RemediationType.ENROLL_AUTHENTICATOR);

        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        authenticationResponse.setIdxClientContext(idxClientContext);
        return authenticationResponse;
    }

    /**
     * Verify the Email authenticator enrollment process with the user supplied email passcode.
     *
     * @param client                the IDX Client
     * @param idxClientContext      the IDC Client context
     * @param passcode              the user supplied email passcode
     * @return the Authentication response
     */
    public static AuthenticationResponse verifyEmailAuthenticator(IDXClient client,
                                                                  IDXClientContext idxClientContext,
                                                                  String passcode) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            IDXResponse introspectResponse = client.introspect(idxClientContext);
            String stateHandle = introspectResponse.getStateHandle();

            RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();

            RemediationOption remediationOption =
                    extractRemediationOption(remediationOptions, RemediationType.ENROLL_AUTHENTICATOR);

            Credentials credentials = new Credentials();
            credentials.setPasscode(passcode.toCharArray());

            // build answer password authenticator challenge request
            AnswerChallengeRequest challengeAuthenticatorRequest = AnswerChallengeRequestBuilder.builder()
                    .withStateHandle(stateHandle)
                    .withCredentials(credentials)
                    .build();

            IDXResponse challengeAuthenticatorResponse =
                    remediationOption.proceed(client, challengeAuthenticatorRequest);

            if (challengeAuthenticatorResponse.remediation() != null) {
                remediationOptions = challengeAuthenticatorResponse.remediation().remediationOptions();
                printRemediationOptions(remediationOptions);

                // check if skip is present in remediation options, if yes skip it (we'll process only mandatory authenticators)
                try {
                    extractRemediationOption(remediationOptions, RemediationType.SKIP);
                } catch (IllegalArgumentException e) {
                    logger.warn("Skip authenticator not found in remediation option");
                    extractRemediationOption(remediationOptions, RemediationType.SELECT_AUTHENTICATOR_ENROLL);
                }
            }

            if (challengeAuthenticatorResponse.isLoginSuccessful()) {
                // login successful
                logger.info("Login Successful!");
                TokenResponse tokenResponse = challengeAuthenticatorResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                authenticationResponse.setTokenResponse(tokenResponse);
            }
        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        authenticationResponse.setIdxClientContext(idxClientContext);
        return authenticationResponse;
    }

    /**
     * Verify the Password authenticator enrollment process with the user supplied password.
     *
     * @param client                the IDX Client
     * @param idxClientContext      the IDC Client context
     * @param password              the user chosen password
     * @return the Authentication response
     */
    public static AuthenticationResponse verifyPasswordAuthenticator(IDXClient client,
                                                                     IDXClientContext idxClientContext,
                                                                     String password) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            IDXResponse introspectResponse = client.introspect(idxClientContext);
            String stateHandle = introspectResponse.getStateHandle();

            RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();

            RemediationOption remediationOption =
                    extractRemediationOption(remediationOptions, RemediationType.ENROLL_AUTHENTICATOR);

            Credentials credentials = new Credentials();
            credentials.setPasscode(password.toCharArray());

            // build answer password authenticator challenge request
            AnswerChallengeRequest challengeAuthenticatorRequest = AnswerChallengeRequestBuilder.builder()
                    .withStateHandle(stateHandle)
                    .withCredentials(credentials)
                    .build();

            IDXResponse challengeAuthenticatorResponse =
                    remediationOption.proceed(client, challengeAuthenticatorRequest);

            if (challengeAuthenticatorResponse.remediation() != null) {
                remediationOptions = challengeAuthenticatorResponse.remediation().remediationOptions();
                printRemediationOptions(remediationOptions);

                // check if skip is present in remediation options, if yes skip it.
                // (we'll process only mandatory authenticators for now)
                try {
                    extractRemediationOption(remediationOptions, RemediationType.SKIP);
                } catch (IllegalArgumentException e) {
                    logger.warn("Skip authenticator not found in remediation option");
                    extractRemediationOption(remediationOptions, RemediationType.SELECT_AUTHENTICATOR_ENROLL);
                }
            }

            if (challengeAuthenticatorResponse.isLoginSuccessful()) {
                // login successful
                logger.info("Login Successful!");
                TokenResponse tokenResponse = challengeAuthenticatorResponse.getSuccessWithInteractionCode().exchangeCode(client, idxClientContext);
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
                authenticationResponse.setTokenResponse(tokenResponse);
            }
        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
        }

        authenticationResponse.setIdxClientContext(idxClientContext);
        return authenticationResponse;
    }

    /**
     * Skip optional authenticator enrollment.
     *
     * @param client                the IDX Client
     * @param idxClientContext      the IDC Client context
     * @return the Authentication response
     */
    public static AuthenticationResponse skipAuthenticatorEnrollment(IDXClient client,
                                                                     IDXClientContext idxClientContext) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            IDXResponse introspectResponse = client.introspect(idxClientContext);
            String stateHandle = introspectResponse.getStateHandle();

            RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();

            RemediationOption remediationOption = extractRemediationOption(remediationOptions, RemediationType.SKIP);

            SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest =
                    SkipAuthenticatorEnrollmentRequestBuilder.builder()
                    .withStateHandle(stateHandle)
                    .build();

            remediationOption.proceed(client, skipAuthenticatorEnrollmentRequest);

        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        authenticationResponse.setIdxClientContext(idxClientContext);
        return authenticationResponse;
    }

    /**
     * Helper to populate the UI options to be shown on Authenticator options page.
     *
     * @param client                the IDX Client
     * @param idxClientContext      the IDC Client context
     * @return the list of {@link AuthenticatorUIOption} options
     */
    public static List<AuthenticatorUIOption> populateAuthenticatorUIOptions(IDXClient client,
                                                                             IDXClientContext idxClientContext) {

        List<AuthenticatorUIOption> authenticatorUIOptionList = new LinkedList<>();

        try {
            IDXResponse introspectResponse = client.introspect(idxClientContext);

            RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();
            printRemediationOptions(remediationOptions);

            RemediationOption remediationOption =
                    extractRemediationOption(remediationOptions, RemediationType.SELECT_AUTHENTICATOR_ENROLL);

            Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();

            for (Map.Entry<String, String> entry : authenticatorOptions.entrySet()) {
                authenticatorUIOptionList.add(new AuthenticatorUIOption(entry.getValue(), entry.getKey()));
            }
        } catch (Exception e) {
            logger.error("Error occurred:", e);
        }

        return authenticatorUIOptionList;
    }

    /**
     * Helper to parse {@link ProcessingException} and populate {@link AuthenticationResponse}
     * with appropriate error messages.
     *
     * @param e the {@link ProcessingException} reference
     * @param authenticationResponse the {@link AuthenticationResponse} reference
     */
    private static void handleProcessingException(ProcessingException e,
                                                  AuthenticationResponse authenticationResponse) {
        logger.error("Exception occurred", e);
        ErrorResponse errorResponse = e.getErrorResponse();
        if (errorResponse != null) {
            if (errorResponse.getMessages() != null) {
                Arrays.stream(errorResponse.getMessages().getValue())
                        .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
            } else {
                authenticationResponse.addError(errorResponse.getError() + ":" + errorResponse.getErrorDescription());
            }
        } else {
            authenticationResponse.addError(e.getMessage());
        }
        logger.error("Error Detail: {}", authenticationResponse.getErrors());
    }

    /**
     * Helper to parse {@link ProcessingException} and populate {@link NewUserRegistrationResponse}
     * with appropriate error messages.
     *
     * @param e the {@link ProcessingException} reference
     * @param newUserRegistrationResponse the {@link NewUserRegistrationResponse} reference
     */
    private static void handleProcessingException(ProcessingException e,
                                                  NewUserRegistrationResponse newUserRegistrationResponse) {
        logger.error("Exception occurred", e);
        ErrorResponse errorResponse = e.getErrorResponse();
        if (errorResponse != null) {
            if (errorResponse.getMessages() != null) {
                Arrays.stream(errorResponse.getMessages().getValue())
                        .forEach(msg -> newUserRegistrationResponse.addError(msg.getMessage()));
            } else {
                newUserRegistrationResponse.addError(errorResponse.getError() + ":" + errorResponse.getErrorDescription());
            }
        } else {
            newUserRegistrationResponse.addError(e.getMessage());
        }
        logger.error("Error Detail: {}", newUserRegistrationResponse.getErrors());
    }

    /**
     * Helper to check if we have landed terminal success/no more remediation steps to follow.
     *
     * @param client                the IDX Client
     * @param idxClientContext      the IDC Client context
     * @return true if login is successful and if there are no more remediation steps to follow; false otherwise.
     */
    public static boolean isTerminalSuccess(IDXClient client,
                                            IDXClientContext idxClientContext) {
        try {
            return client.introspect(idxClientContext).isLoginSuccessful();
        } catch (ProcessingException e) {
            logger.error("Error occurred:", e);
            return false;
        }
    }

    /**
     * Helper to check if we have optional authenticators to skip in current remediation step.
     *
     * @param client                the IDX Client
     * @param idxClientContext      the IDC Client context
     * @return true if we have optional authenticators to skip; false otherwise.
     */

    public static boolean isSkipAuthenticatorPresent(IDXClient client, IDXClientContext idxClientContext) {
        try {
            IDXResponse introspectResponse = client.introspect(idxClientContext);

            RemediationOption[] remediationOptions = introspectResponse.remediation().remediationOptions();
            printRemediationOptions(remediationOptions);

            extractRemediationOption(remediationOptions, RemediationType.SKIP);
        } catch (IllegalArgumentException e) {
            return false;
        } catch (ProcessingException e) {
            logger.error("Error occurred:", e);
            return false;
        }

        return true;
    }

    private static boolean isRemediationRequireCredentials(String remediationOptionName,
                                                           IDXResponse idxResponse) {
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();

        Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                .filter(x -> remediationOptionName.equals(x.getName()))
                .findFirst();
        Assert.isTrue(remediationOptionsOptional.isPresent(),
                "Missing remediation option " + remediationOptionName);

        RemediationOption remediationOption = remediationOptionsOptional.get();
        FormValue[] formValues = remediationOption.form();

        Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                .filter(x -> "credentials".equals(x.getName()))
                .findFirst();

        return credentialsFormValueOptional.isPresent();
    }

    private static RemediationOption extractRemediationOption(RemediationOption[] remediationOptions,
                                                              String remediationType) {
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