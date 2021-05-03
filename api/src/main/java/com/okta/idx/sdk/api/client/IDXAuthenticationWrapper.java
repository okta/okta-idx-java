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
package com.okta.idx.sdk.api.client;

import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.AuthenticationOptions;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.Authenticator;
import com.okta.idx.sdk.api.model.AuthenticatorType;
import com.okta.idx.sdk.api.model.AuthenticatorUIOption;
import com.okta.idx.sdk.api.model.AuthenticatorUIOptions;
import com.okta.idx.sdk.api.model.AuthenticatorsValue;
import com.okta.idx.sdk.api.model.ChangePasswordOptions;
import com.okta.idx.sdk.api.model.Credentials;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.Recover;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.RemediationType;
import com.okta.idx.sdk.api.model.TokenType;
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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Wrapper to enable a client to interact with the backend IDX APIs.
 */
public class IDXAuthenticationWrapper {

    private static final Logger logger = LoggerFactory.getLogger(IDXAuthenticationWrapper.class);

    private final IDXClient client;

    /**
     * Creates {@link IDXAuthenticationWrapper} instance.
     */
    public IDXAuthenticationWrapper() {
        this.client = Clients.builder().build();
    }

    /**
     * Creates {@link IDXAuthenticationWrapper} instance.
     *
     * @param issuer the issuer url
     * @param clientId the client id
     * @param clientSecret the client secret
     * @param scopes the set of scopes
     * @param redirectUri the redirect uri
     */
    public IDXAuthenticationWrapper(String issuer, String clientId, String clientSecret,
                                    Set<String> scopes, String redirectUri) {
        this.client = Clients.builder()
                .setIssuer(issuer)
                .setClientId(clientId)
                .setClientSecret(clientSecret)
                .setScopes(scopes)
                .setRedirectUri(redirectUri)
                .build();
    }

    /**
     * Authenticate user with the supplied Authentication options (username and password) and
     * returns the Authentication response object that contains:
     * - IDX Client context
     * - Token (access_token/id_token/refresh_token) object
     * - Authentication status
     * <p>
     * Note: This requires 'Password' as the ONLY required factor in app Sign-on policy configuration.
     *
     * @param authenticationOptions the Authenticator options
     * @return the Authentication response
     */
    public AuthenticationResponse authenticate(AuthenticationOptions authenticationOptions) {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.create(client);

            // Check if identify flow needs to include credentials
            boolean isIdentifyInOneStep = introspectTransaction.isRemediationRequireCredentials(RemediationType.IDENTIFY);

            IdentifyRequest identifyRequest;

            if (isIdentifyInOneStep) {
                Credentials credentials = new Credentials();
                credentials.setPasscode(authenticationOptions.getPassword().toCharArray());

                identifyRequest = IdentifyRequestBuilder.builder()
                        .withIdentifier(authenticationOptions.getUsername())
                        .withCredentials(credentials)
                        .withStateHandle(introspectTransaction.getStateHandle())
                        .build();
            } else {
                identifyRequest = IdentifyRequestBuilder.builder()
                        .withIdentifier(authenticationOptions.getUsername())
                        .withStateHandle(introspectTransaction.getStateHandle())
                        .build();
            }

            // identify user
            AuthenticationTransaction identifyTransaction = introspectTransaction.proceed(() ->
                    introspectTransaction.getRemediationOption(RemediationType.IDENTIFY).proceed(client, identifyRequest)
            );

            if (isIdentifyInOneStep) {
                return identifyTransaction.asAuthenticationResponse();
            } else {
                AuthenticationTransaction passwordTransaction = selectPasswordAuthenticatorIfNeeded(identifyTransaction);
                AuthenticationTransaction answerTransaction = passwordTransaction.proceed(() -> {
                    // answer password authenticator challenge
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(authenticationOptions.getPassword().toCharArray());

                    // build answer password authenticator challenge request
                    AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest =
                            AnswerChallengeRequestBuilder.builder()
                                    .withStateHandle(passwordTransaction.getStateHandle())
                                    .withCredentials(credentials)
                                    .build();

                    return passwordTransaction.getRemediationOption(RemediationType.CHALLENGE_AUTHENTICATOR).proceed(client, passwordAuthenticatorAnswerChallengeRequest);
                });
                return answerTransaction.asAuthenticationResponse();
            }
        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        return authenticationResponse;
    }

    // If app sign-on policy is set to "any 1 factor", the next remediation after identify is
    // select-authenticator-authenticate
    // Check if that's the case, and proceed to select password authenticator
    private AuthenticationTransaction selectPasswordAuthenticatorIfNeeded(AuthenticationTransaction authenticationTransaction) throws ProcessingException {
        Optional<RemediationOption> remediationOptionOptional = authenticationTransaction.getOptionalRemediationOption(RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE);
        if (!remediationOptionOptional.isPresent()) {
            // We don't need to.
            return authenticationTransaction;
        }
        Map<String, String> authenticatorOptions = remediationOptionOptional.get().getAuthenticatorOptions();

        Authenticator authenticator = new Authenticator();
        authenticator.setId(authenticatorOptions.get("password"));

        ChallengeRequest selectAuthenticatorRequest = ChallengeRequestBuilder.builder()
                .withStateHandle(authenticationTransaction.getStateHandle())
                .withAuthenticator(authenticator)
                .build();

        return authenticationTransaction.proceed(() ->
                remediationOptionOptional.get().proceed(client, selectAuthenticatorRequest)
        );
    }

    /**
     * Change password with the supplied change password options reference.
     *
     * @param idxClientContext      the IDX Client context
     * @return the Authentication response
     */
    public AuthenticationResponse changePassword(IDXClientContext idxClientContext,
                                                 ChangePasswordOptions changePasswordOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            // re-enter flow with context
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.introspect(client, idxClientContext);

            // check if flow is password expiration or forgot password
            RemediationOption resetAuthenticatorRemediationOption =
                    introspectTransaction.getRemediationOption(RemediationType.RESET_AUTHENTICATOR, RemediationType.REENROLL_AUTHENTICATOR);

            // set new password
            Credentials credentials = new Credentials();
            credentials.setPasscode(changePasswordOptions.getNewPassword().toCharArray());

            // build answer password authenticator challenge request
            AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest =
                    AnswerChallengeRequestBuilder.builder()
                            .withStateHandle(introspectTransaction.getStateHandle())
                            .withCredentials(credentials)
                            .build();

            return introspectTransaction.proceed(() ->
                    resetAuthenticatorRemediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest)
            ).asAuthenticationResponse();
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
     * Recover Password with the supplied username.
     *
     * @param username the username
     * @return the Authentication response
     */
    public AuthenticationResponse recoverPassword(String username) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.create(client);
            authenticationResponse.setIdxClientContext(introspectTransaction.getClientContext());

            boolean isIdentifyInOneStep = introspectTransaction.isRemediationRequireCredentials(RemediationType.IDENTIFY);

            if (isIdentifyInOneStep) {
                // recover
                RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
                        .withStateHandle(introspectTransaction.getStateHandle())
                        .build();

                AuthenticationTransaction recoverTransaction = introspectTransaction.proceed(() ->
                        client.recover(recoverRequest, null)
                );

                RemediationOption remediationOption = recoverTransaction.getRemediationOption(RemediationType.IDENTIFY_RECOVERY);

                IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
                        .withIdentifier(username)
                        .withStateHandle(introspectTransaction.getStateHandle())
                        .build();

                // identify user
                return recoverTransaction.proceed(() ->
                        remediationOption.proceed(client, identifyRequest)
                ).asAuthenticationResponse(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION);
            } else {
                RemediationOption remediationOption = introspectTransaction.getRemediationOption(RemediationType.IDENTIFY);

                IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
                        .withIdentifier(username)
                        .withStateHandle(introspectTransaction.getStateHandle())
                        .build();

                // identify user
                AuthenticationTransaction identifyTransaction = introspectTransaction.proceed(() ->
                        remediationOption.proceed(client, identifyRequest)
                );
                IDXResponse identifyResponse = identifyTransaction.getResponse();

                if (identifyResponse.getMessages() != null) {
                    return identifyTransaction.asAuthenticationResponse(AuthenticationStatus.AWAITING_USER_EMAIL_ACTIVATION);
                }

                // Check if instead of password, user is being prompted for list of authenticators to select
                if (identifyResponse.getCurrentAuthenticatorEnrollment() == null) {
                    identifyTransaction = selectPasswordAuthenticatorIfNeeded(identifyTransaction);
                }

                return identifyTransaction.asAuthenticationResponse(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION);
            }
        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        return authenticationResponse;
    }

    /**
     * Get the authenticator options for the forgot password remediation.
     *
     * @param idxClientContext the idxClientContext
     * @return the list of AuthenticatorUIOptions
     */
    public AuthenticatorUIOptions populateForgotPasswordAuthenticatorUIOptions(
            IDXClientContext idxClientContext) {

        AuthenticatorUIOptions authenticatorUIOptions = new AuthenticatorUIOptions();
        List<AuthenticatorUIOption> authenticatorUIOptionList = new LinkedList<>();

        try {
            AuthenticationTransaction introspectTransaction =
                    AuthenticationTransaction.introspect(client, idxClientContext);

            Recover recover = introspectTransaction.getResponse()
                    .getCurrentAuthenticatorEnrollment().getValue().getRecover();

            AuthenticationTransaction recoverTransaction = introspectTransaction.proceed(() -> {
                // recover password
                RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
                        .withStateHandle(introspectTransaction.getStateHandle())
                        .build();
                return recover.proceed(client, recoverRequest);
            });

            RemediationOption remediationOption =
                    recoverTransaction.getRemediationOption(RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE);

            Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();

            for (Map.Entry<String, String> entry : authenticatorOptions.entrySet()) {
                if (!entry.getKey().equals(AuthenticatorType.PASSWORD.getValue()) &&
                        !entry.getKey().equals(AuthenticatorType.EMAIL.getValue()) &&
                        !entry.getKey().equals(AuthenticatorType.SMS.getValue())) {
                    logger.info("Skipping unsupported authenticator - {}", entry.getKey());
                    continue;
                }
                authenticatorUIOptionList.add(new AuthenticatorUIOption(entry.getValue(), entry.getKey()));
            }
        } catch (ProcessingException e) {
            logger.error("Error occurred:", e);
            authenticatorUIOptions.setErrors(fillProcessingErrors(e));
        }

        authenticatorUIOptions.setOptions(authenticatorUIOptionList);
        return authenticatorUIOptions;
    }

    /**
     * Select the next authenticator type to remediate.
     *
     * @param idxClientContext the idxClientContext
     * @param authenticatorType the authenticator type
     * @return the Authentication response
     */
    public AuthenticationResponse selectForgotPasswordAuthenticator(IDXClientContext idxClientContext,
                                                                    String authenticatorType) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setIdxClientContext(idxClientContext);

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.introspect(client, idxClientContext);

            // recover password
            RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
                    .withStateHandle(introspectTransaction.getStateHandle())
                    .build();

            AuthenticationTransaction recoverTransaction = introspectTransaction;
            if (introspectTransaction.getResponse().getCurrentAuthenticatorEnrollment() != null) {
                Recover recover = introspectTransaction.getResponse().getCurrentAuthenticatorEnrollment().getValue().getRecover();
                recoverTransaction = introspectTransaction.proceed(() ->
                        recover.proceed(client, recoverRequest)
                );
            }

            RemediationOption remediationOption = recoverTransaction.getRemediationOption(RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE);

            Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();

            Authenticator authenticator = new Authenticator();

            authenticator.setId(authenticatorOptions.get(authenticatorType));

            ChallengeRequest selectAuthenticatorRequest = ChallengeRequestBuilder.builder()
                    .withStateHandle(introspectTransaction.getStateHandle())
                    .withAuthenticator(authenticator)
                    .build();

            AuthenticationTransaction selectAuthenticatorResponse = recoverTransaction.proceed(() ->
                    remediationOption.proceed(client, selectAuthenticatorRequest)
            );

            // Validate we're in the right state and have the correct authenticator.
            selectAuthenticatorResponse.getRemediationOption(RemediationType.CHALLENGE_AUTHENTICATOR);

            return selectAuthenticatorResponse.asAuthenticationResponse(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION);
        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        return authenticationResponse;
    }

    /**
     * Populate UI form values for signing up a new user.
     *
     * @return the new user registration response
     */
    public NewUserRegistrationResponse fetchSignUpFormValues() {

        List<FormValue> enrollProfileFormValues;

        NewUserRegistrationResponse newUserRegistrationResponse = new NewUserRegistrationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.create(client);
            newUserRegistrationResponse.setIdxClientContext(introspectTransaction.getClientContext());

            // enroll new user
            AuthenticationTransaction enrollTransaction = introspectTransaction.proceed(() -> {
                RemediationOption selectEnrollProfileRemediationOption =
                        introspectTransaction.getRemediationOption(RemediationType.SELECT_ENROLL_PROFILE);

                EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                        .withStateHandle(introspectTransaction.getStateHandle())
                        .build();
                return selectEnrollProfileRemediationOption.proceed(client, enrollRequest);
            });


            RemediationOption enrollProfileRemediationOption =
                    enrollTransaction.getRemediationOption(RemediationType.ENROLL_PROFILE);

            enrollProfileFormValues = Arrays.stream(enrollProfileRemediationOption.form())
                    .filter(x -> "userProfile".equals(x.getName()))
                    .collect(Collectors.toList());

            newUserRegistrationResponse.setFormValues(enrollProfileFormValues);
        } catch (ProcessingException e) {
            handleProcessingException(e, newUserRegistrationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            newUserRegistrationResponse.addError(e.getMessage());
        }

        return newUserRegistrationResponse;
    }

    /**
     * Register new user with the supplied user profile reference.
     *
     * @param idxClientContext      the IDX Client context
     * @param userProfile           the user profile
     * @return the Authentication response
     */
    public AuthenticationResponse register(IDXClientContext idxClientContext,
                                           UserProfile userProfile) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.introspect(client, idxClientContext);

            AuthenticationTransaction enrollTransaction = introspectTransaction.proceed(() -> {
                RemediationOption remediationOption =
                        introspectTransaction.getRemediationOption(RemediationType.ENROLL_PROFILE);

                EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest =
                        EnrollUserProfileUpdateRequestBuilder.builder()
                                .withUserProfile(userProfile)
                                .withStateHandle(introspectTransaction.getStateHandle())
                                .build();
                return remediationOption.proceed(client, enrollUserProfileUpdateRequest);
            });

            // Verify the next remediation is correct.
            enrollTransaction.getRemediationOption(RemediationType.SELECT_AUTHENTICATOR_ENROLL);

            return enrollTransaction.asAuthenticationResponse(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION);
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
     * Select authenticator of the supplied type.
     *
     * @param idxClientContext      the IDX Client context
     * @param authenticatorType     the authenticator type
     * @return the Authentication response
     */
    public AuthenticationResponse selectAuthenticator(IDXClientContext idxClientContext, String authenticatorType) {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.introspect(client, idxClientContext);
            RemediationOption remediationOption =
                    introspectTransaction.getRemediationOption(RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE);
            return introspectTransaction.proceed(() -> {
                Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
                Authenticator authenticator = new Authenticator();
                authenticator.setId(authenticatorOptions.get(authenticatorType));
                ChallengeRequest request = ChallengeRequestBuilder.builder()
                        .withStateHandle(introspectTransaction.getStateHandle())
                        .withAuthenticator(authenticator)
                        .build();
                return remediationOption.proceed(client, request);
            }).asAuthenticationResponse();
        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        return authenticationResponse;
    }

    /**
     * Verify the email code from the authentication process with the user supplied email passcode.
     *
     * @param idxClientContext      the IDX Client context
     * @param passcode              the user supplied email passcode
     * @return the Authentication response
     */
    public AuthenticationResponse authenticateEmail(IDXClientContext idxClientContext,
            String passcode) {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.introspect(client, idxClientContext);
            return introspectTransaction.proceed(() -> {
                Credentials credentials = new Credentials();
                credentials.setPasscode(passcode.toCharArray());

                // build answer password authenticator challenge request
                AnswerChallengeRequest challengeAuthenticatorRequest = AnswerChallengeRequestBuilder.builder()
                        .withStateHandle(introspectTransaction.getStateHandle())
                        .withCredentials(credentials)
                        .build();

                return introspectTransaction.getRemediationOption(RemediationType.CHALLENGE_AUTHENTICATOR).proceed(client, challengeAuthenticatorRequest);
            }).asAuthenticationResponse();
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
     * @param idxClientContext      the IDX Client context
     * @param authenticatorType     the authenticator type
     * @return the Authentication response
     */
    public AuthenticationResponse enrollAuthenticator(IDXClientContext idxClientContext,
                                                      String authenticatorType) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.introspect(client, idxClientContext);

            return introspectTransaction.proceed(() -> {
                RemediationOption remediationOption =
                        introspectTransaction.getRemediationOption(RemediationType.SELECT_AUTHENTICATOR_ENROLL);

                Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
                logger.info("Authenticator Options: {}", authenticatorOptions);

                Authenticator authenticator = new Authenticator();

                AuthenticatorType authType = AuthenticatorType.get(authenticatorType);

                if (authType == null) {
                    String errMsg = "Unsupported authenticator " + authenticatorType;
                    logger.error(errMsg);
                    throw new IllegalArgumentException(errMsg);
                }

                authenticator.setId(authenticatorOptions.get(authType.toString()));
                authenticator.setMethodType(authType.toString());

                EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                        .withAuthenticator(authenticator)
                        .withStateHandle(introspectTransaction.getStateHandle())
                        .build();

                return remediationOption.proceed(client, enrollRequest);
            }).asAuthenticationResponse();
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
     * @param idxClientContext      the IDX Client context
     * @param verifyAuthenticatorOptions the verify Authenticator options
     * @return the Authentication response
     */
    public AuthenticationResponse verifyAuthenticator(IDXClientContext idxClientContext,
                                                      VerifyAuthenticatorOptions verifyAuthenticatorOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.introspect(client, idxClientContext);

            Optional<RemediationOption> enrollAuthenticatorOptional =
                    introspectTransaction.getOptionalRemediationOption(RemediationType.ENROLL_AUTHENTICATOR);
            RemediationOption remediationOption = enrollAuthenticatorOptional.orElseGet(() ->
                    introspectTransaction.getRemediationOption(RemediationType.CHALLENGE_AUTHENTICATOR)
            );

            Credentials credentials = new Credentials();
            credentials.setPasscode(verifyAuthenticatorOptions.getCode().toCharArray());

            // build answer password authenticator challenge request
            AnswerChallengeRequest challengeAuthenticatorRequest = AnswerChallengeRequestBuilder.builder()
                    .withStateHandle(introspectTransaction.getStateHandle())
                    .withCredentials(credentials)
                    .build();

            return introspectTransaction.proceed(() ->
                    remediationOption.proceed(client, challengeAuthenticatorRequest)
            ).asAuthenticationResponse(AuthenticationStatus.AWAITING_PASSWORD_RESET);

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
     * Submit phone authenticator enrollment with the provided phone number.
     *
     * @param idxClientContext    the IDX Client context
     * @param phone               the phone number
     * @param mode                the delivery mode - sms or voice
     * @return the Authentication response
     */
    public AuthenticationResponse submitPhoneAuthenticator(IDXClientContext idxClientContext,
                                                           String phone,
                                                           String mode) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.introspect(client, idxClientContext);

            RemediationOption remediationOption =
                    introspectTransaction.getRemediationOption(RemediationType.AUTHENTICATOR_ENROLLMENT_DATA);

            AuthenticatorsValue[] authenticators = introspectTransaction.getResponse().getAuthenticators().getValue();
            Optional<AuthenticatorsValue> authenticatorsValueOptional = Arrays.stream(authenticators)
                    .filter(x -> "phone_number".equals(x.getKey()))
                    .findAny();
            AuthenticatorsValue authenticatorsValue = authenticatorsValueOptional.get();

            Authenticator phoneAuthenticator = new Authenticator();
            phoneAuthenticator.setId(authenticatorsValue.getId());
            phoneAuthenticator.setMethodType(AuthenticatorType.get(mode).toString());
            phoneAuthenticator.setPhoneNumber(phone);

            EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                    .withAuthenticator(phoneAuthenticator)
                    .withStateHandle(introspectTransaction.getStateHandle())
                    .build();

            return introspectTransaction.proceed(() ->
                    remediationOption.proceed(client, enrollRequest)
            ).asAuthenticationResponse();
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
     * @param idxClientContext      the IDX Client context
     * @return the Authentication response
     */
    public AuthenticationResponse skipAuthenticatorEnrollment(IDXClientContext idxClientContext) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.introspect(client, idxClientContext);
            RemediationOption remediationOption = introspectTransaction.getRemediationOption(RemediationType.SKIP);

            SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest =
                    SkipAuthenticatorEnrollmentRequestBuilder.builder()
                            .withStateHandle(introspectTransaction.getStateHandle())
                            .build();

            return introspectTransaction.proceed(() ->
                    remediationOption.proceed(client, skipAuthenticatorEnrollmentRequest)
            ).asAuthenticationResponse(AuthenticationStatus.SKIP_COMPLETE);

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
     * @param idxClientContext      the IDX Client context
     * @return the list of {@link AuthenticatorUIOption} options
     */
    public List<AuthenticatorUIOption> populateAuthenticatorUIOptions(IDXClientContext idxClientContext) {

        List<AuthenticatorUIOption> authenticatorUIOptionList = new ArrayList<>();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.introspect(client, idxClientContext);
            if (introspectTransaction.getResponse().remediation() == null) {
                return authenticatorUIOptionList;
            }

            RemediationOption remediationOption = null;

            Optional<RemediationOption> selectAuthenticatorEnrollOptional = introspectTransaction.getOptionalRemediationOption(RemediationType.SELECT_AUTHENTICATOR_ENROLL);
            if (selectAuthenticatorEnrollOptional.isPresent()) {
                remediationOption = selectAuthenticatorEnrollOptional.get();
            }

            Optional<RemediationOption> selectAuthenticatorAuthenticateOptional = introspectTransaction.getOptionalRemediationOption(RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE);
            if (selectAuthenticatorAuthenticateOptional.isPresent()) {
                remediationOption = selectAuthenticatorAuthenticateOptional.get();
            }

            if (remediationOption == null) {
                return new ArrayList<>();
            }

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
     * Get IDX client context by calling the interact endpoint.
     * ClientContext reference contains the interaction handle and PKCE params.
     *
     * @return the idx client context
     */
    public IDXClientContext getClientContext() {

        IDXClientContext idxClientContext = null;

        try {
            idxClientContext = client.interact();
        } catch (ProcessingException e) {
            logger.error("Error occurred:", e);
        }

        return idxClientContext;
    }

    /**
     * Revoke the oauth2 token.
     *
     * @param tokenType the token type (access|refresh)
     * @param token the token
     */
    public void revokeToken(TokenType tokenType, String token) {

        try {
            client.revokeToken(tokenType.toString(), token);
        } catch (ProcessingException e) {
            logger.error("Exception occurred", e);
        }
    }

    /**
     * Helper to parse {@link ProcessingException} and populate {@link AuthenticationResponse}
     * with appropriate error messages.
     *
     * @param e the {@link ProcessingException} reference
     * @param authenticationResponse the {@link AuthenticationResponse} reference
     */
    private void handleProcessingException(ProcessingException e,
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
     * Helper to parse {@link ProcessingException} and return a list of error messages.
     *
     * @param e the {@link ProcessingException} reference
     */
    private List<String> fillProcessingErrors(ProcessingException e) {
        logger.error("Exception occurred", e);
        List<String> processingErrors = new LinkedList<>();
        ErrorResponse errorResponse = e.getErrorResponse();
        if (errorResponse != null) {
            if (errorResponse.getMessages() != null) {
                Arrays.stream(errorResponse.getMessages().getValue())
                        .forEach(msg -> processingErrors.add(msg.getMessage()));
            } else {
                processingErrors.add(errorResponse.getError() + ":" + errorResponse.getErrorDescription());
            }
        } else {
            processingErrors.add(e.getMessage());
        }

        logger.error("Error Detail: {}", processingErrors);
        return processingErrors;
    }

    /**
     * Helper to parse {@link ProcessingException} and populate {@link NewUserRegistrationResponse}
     * with appropriate error messages.
     *
     * @param e the {@link ProcessingException} reference
     * @param newUserRegistrationResponse the {@link NewUserRegistrationResponse} reference
     */
    private void handleProcessingException(ProcessingException e,
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
     * @param idxClientContext      the IDX Client context
     * @return true if login is successful and if there are no more remediation steps to follow; false otherwise.
     */
    public boolean isTerminalSuccess(IDXClientContext idxClientContext) {
        try {
            AuthenticationTransaction transaction = AuthenticationTransaction.introspect(client, idxClientContext);
            return transaction.getResponse().isLoginSuccessful();
        } catch (ProcessingException e) {
            logger.error("Error occurred:", e);
            return false;
        }
    }

    /**
     * Helper to check if we have optional authenticators to skip in current remediation step.
     *
     * @param idxClientContext      the IDX Client context
     * @return true if we have optional authenticators to skip; false otherwise.
     */
    public boolean isSkipAuthenticatorPresent(IDXClientContext idxClientContext) {
        try {
            AuthenticationTransaction transaction = AuthenticationTransaction.introspect(client, idxClientContext);
            return transaction.getOptionalRemediationOption(RemediationType.SKIP).isPresent();
        } catch (IllegalArgumentException e) {
            return false;
        } catch (ProcessingException e) {
            logger.error("Error occurred:", e);
            return false;
        }
    }
}
