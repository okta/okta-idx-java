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
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.NewUserRegistrationResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static com.okta.idx.sdk.api.client.WrapperUtil.getSelectAuthenticatorRemediationOption;
import static com.okta.idx.sdk.api.client.WrapperUtil.handleProcessingException;

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

            authenticationResponse.setAuthenticatorUIOptions(
                    populateAuthenticatorUIOptions(introspectTransaction));

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

                    return passwordTransaction.getRemediationOption(RemediationType.CHALLENGE_AUTHENTICATOR)
                            .proceed(client, passwordAuthenticatorAnswerChallengeRequest);
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

    /**
     * Change password with the supplied change password options reference.
     *
     * @param proceedContext      the ProceedContext
     * @return the Authentication response
     */
    public AuthenticationResponse changePassword(ProceedContext proceedContext,
                                                 ChangePasswordOptions changePasswordOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            return AuthenticationTransaction.proceed(client, proceedContext, () -> {
                // set new password
                Credentials credentials = new Credentials();
                credentials.setPasscode(changePasswordOptions.getNewPassword().toCharArray());

                // build answer password authenticator challenge request
                AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest =
                        AnswerChallengeRequestBuilder.builder()
                                .withStateHandle(proceedContext.getStateHandle())
                                .withCredentials(credentials)
                                .build();
                return client.answerChallenge(passwordAuthenticatorAnswerChallengeRequest, proceedContext.getHref());
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
     * Recover Password with the supplied username.
     *
     * @param username the username
     * @return the Authentication response
     */
    public AuthenticationResponse recoverPassword(String username) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction introspectTransaction = AuthenticationTransaction.create(client);

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

                IDXResponse identifyResponse = remediationOption.proceed(client, identifyRequest);

                // identify user
                AuthenticationResponse response = recoverTransaction.proceed(() ->
                        identifyResponse
                ).asAuthenticationResponse(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION);
                AuthenticationTransaction tmp = new AuthenticationTransaction(client, introspectTransaction.getClientContext(), identifyResponse);
                response.setAuthenticatorUIOptions(populateAuthenticatorUIOptions(tmp));
                return response;
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

                Recover recover = identifyTransaction.getResponse()
                        .getCurrentAuthenticatorEnrollment().getValue().getRecover();

                AuthenticationTransaction recoverTransaction = introspectTransaction.proceed(() -> {
                    // recover password
                    RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
                            .withStateHandle(introspectTransaction.getStateHandle())
                            .build();
                    return recover.proceed(client, recoverRequest);
                });

                return recoverTransaction.asAuthenticationResponse(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION);
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
     * Register new user with the supplied user profile reference.
     *
     * @param proceedContext      the ProceedContext
     * @param userProfile           the user profile
     * @return the Authentication response
     */
    public AuthenticationResponse register(ProceedContext proceedContext,
                                           UserProfile userProfile) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            AuthenticationTransaction enrollTransaction = AuthenticationTransaction.proceed(client, proceedContext, () -> {
                EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest =
                        EnrollUserProfileUpdateRequestBuilder.builder()
                                .withUserProfile(userProfile)
                                .withStateHandle(proceedContext.getStateHandle())
                                .build();
                return client.enrollUpdateUserProfile(enrollUserProfileUpdateRequest, proceedContext.getHref());
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

        return authenticationResponse;
    }

    /**
     * Select authenticator of the supplied type.
     *
     * @param proceedContext      the ProceedContext
     * @param factor     the factor
     * @return the Authentication response
     */
    public AuthenticationResponse selectAuthenticator(ProceedContext proceedContext, 
                                                      com.okta.idx.sdk.api.client.Authenticator.Factor factor) {

      AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            return AuthenticationTransaction.proceed(client, proceedContext, () -> {
                Authenticator authenticator = new Authenticator();
                authenticator.setId(factor.getId());
                String enrollmentId = factor.getEnrollmentId();
                String factorType = factor.getMethod();
                if (enrollmentId != null && (factorType.equals("sms") || factorType.equals("voice"))) {
                    authenticator.setEnrollmentId(enrollmentId);
                    authenticator.setMethodType(factorType);
                }
                ChallengeRequest request = ChallengeRequestBuilder.builder()
                        .withStateHandle(proceedContext.getStateHandle())
                        .withAuthenticator(authenticator)
                        .build();
                return client.challenge(request, proceedContext.getHref());
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
     * @param proceedContext      the ProceedContext
     * @param passcode            the user supplied email passcode
     * @return the Authentication response
     */
    public AuthenticationResponse authenticateEmail(ProceedContext proceedContext,
                                                    String passcode) {

      AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            return AuthenticationTransaction.proceed(client, proceedContext, () -> {
                Credentials credentials = new Credentials();
                credentials.setPasscode(passcode.toCharArray());

                // build answer password authenticator challenge request
                AnswerChallengeRequest challengeAuthenticatorRequest = AnswerChallengeRequestBuilder.builder()
                        .withStateHandle(proceedContext.getStateHandle())
                        .withCredentials(credentials)
                        .build();

                return client.answerChallenge(challengeAuthenticatorRequest, proceedContext.getHref());
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
     * Enroll authenticator of the supplied type.
     *
     * @param proceedContext      the ProceedContext
     * @param factor     the factor
     * @return the Authentication response
     */
    public AuthenticationResponse enrollAuthenticator(ProceedContext proceedContext,
                                                      com.okta.idx.sdk.api.client.Authenticator.Factor factor) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            return AuthenticationTransaction.proceed(client, proceedContext, () -> {
                Authenticator authenticator = new Authenticator();

                authenticator.setId(factor.getId());
                authenticator.setMethodType(factor.getMethod());

                EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                        .withAuthenticator(authenticator)
                        .withStateHandle(proceedContext.getStateHandle())
                        .build();

                return client.enroll(enrollRequest, proceedContext.getHref());
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
     * Verify Authenticator with the supplied authenticator options.
     *
     * @param proceedContext      the ProceedContext
     * @param verifyAuthenticatorOptions the verify Authenticator options
     * @return the Authentication response
     */
    public AuthenticationResponse verifyAuthenticator(ProceedContext proceedContext,
                                                      VerifyAuthenticatorOptions verifyAuthenticatorOptions) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            Credentials credentials = new Credentials();
            credentials.setPasscode(verifyAuthenticatorOptions.getCode().toCharArray());

            // build answer password authenticator challenge request
            AnswerChallengeRequest challengeAuthenticatorRequest = AnswerChallengeRequestBuilder.builder()
                    .withStateHandle(proceedContext.getStateHandle())
                    .withCredentials(credentials)
                    .build();

            return AuthenticationTransaction.proceed(client, proceedContext, () ->
                    client.answerChallenge(challengeAuthenticatorRequest, proceedContext.getHref())
            ).asAuthenticationResponse(AuthenticationStatus.AWAITING_PASSWORD_RESET);

        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        return authenticationResponse;
    }

    /**
     * Submit phone authenticator enrollment with the provided phone number.
     *
     * @param proceedContext    the ProceedContext
     * @param phone               the phone number
     * @param factor                factor
     * @return the Authentication response
     */
    public AuthenticationResponse submitPhoneAuthenticator(ProceedContext proceedContext,
                                                           String phone,
                                                           com.okta.idx.sdk.api.client.Authenticator.Factor factor) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            Authenticator phoneAuthenticator = new Authenticator();
            phoneAuthenticator.setId(factor.getId());
            phoneAuthenticator.setMethodType(factor.getMethod());
            phoneAuthenticator.setPhoneNumber(phone);

            EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                    .withAuthenticator(phoneAuthenticator)
                    .withStateHandle(proceedContext.getStateHandle())
                    .build();

            return AuthenticationTransaction.proceed(client, proceedContext, () ->
                    client.enroll(enrollRequest, proceedContext.getHref())
            ).asAuthenticationResponse();
        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
        }

        return authenticationResponse;
    }

    /**
     * Skip optional authenticator enrollment.
     *
     * @param proceedContext      the ProceedContext
     * @return the Authentication response
     */
    public AuthenticationResponse skipAuthenticatorEnrollment(ProceedContext proceedContext) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest =
                    SkipAuthenticatorEnrollmentRequestBuilder.builder()
                            .withStateHandle(proceedContext.getStateHandle())
                            .build();

            return AuthenticationTransaction.proceed(client, proceedContext, () ->
                    client.skip(skipAuthenticatorEnrollmentRequest, proceedContext.getSkipHref())
            ).asAuthenticationResponse(AuthenticationStatus.SKIP_COMPLETE);

        } catch (ProcessingException e) {
            handleProcessingException(e, authenticationResponse);
        } catch (IllegalArgumentException e) {
            logger.error("Exception occurred", e);
            authenticationResponse.addError(e.getMessage());
        }

        return authenticationResponse;
    }

    /**
     * Get IDX client context by calling the interact endpoint.
     * ClientContext reference contains the interaction handle and PKCE params.
     *
     * This function can be used by the client applications to get a handle
     * of {@link IDXClientContext} which can be used to reenter/resume the flow.
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
            authenticatorUIOptionList.add(new AuthenticatorUIOption(entry.getValue(), entry.getKey()));
        }

        authenticatorUIOptions.setOptions(authenticatorUIOptionList);
        return authenticatorUIOptions;
    }

    /**
     * Helper to check if we have optional authenticators to skip in current remediation step.
     *
     * @param proceedContext      the ProceedContext
     * @return true if we have optional authenticators to skip; false otherwise.
     */
    public boolean isSkipAuthenticatorPresent(ProceedContext proceedContext) {
        return proceedContext.getSkipHref() != null;
    }
}
