/*
 * Copyright (c) 2021-Present, Okta, Inc.
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

import com.okta.commons.lang.Assert;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.AuthenticationOptions;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.Authenticator;
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
import com.okta.idx.sdk.api.response.TokenResponse;
import com.okta.idx.sdk.api.util.ClientUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.MalformedURLException;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;

import static com.okta.idx.sdk.api.client.WrapperUtil.handleIllegalArgumentException;
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
    public AuthenticationResponse authenticate(AuthenticationOptions authenticationOptions, ProceedContext proceedContext) {
        try {
            // Check if identify flow needs to include credentials
            boolean isIdentifyInOneStep = proceedContext.isIdentifyInOneStep();

            AuthenticationTransaction identifyTransaction = AuthenticationTransaction.proceed(client, proceedContext, () -> {
                IdentifyRequest identifyRequest;

                if (isIdentifyInOneStep) {
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(authenticationOptions.getPassword().toCharArray());

                    identifyRequest = IdentifyRequestBuilder.builder()
                            .withIdentifier(authenticationOptions.getUsername())
                            .withCredentials(credentials)
                            .withStateHandle(proceedContext.getStateHandle())
                            .build();
                } else {
                    identifyRequest = IdentifyRequestBuilder.builder()
                            .withIdentifier(authenticationOptions.getUsername())
                            .withStateHandle(proceedContext.getStateHandle())
                            .build();
                }

                // identify user
                return client.identify(identifyRequest, proceedContext.getHref());
            });

            AuthenticationResponse identifyResponse = identifyTransaction.asAuthenticationResponse();
            if (isIdentifyInOneStep ||
                    identifyResponse.getErrors() != null && !identifyResponse.getErrors().isEmpty()) {
                return identifyResponse;
            }

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
        } catch (ProcessingException e) {
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    /**
     * Recover Password with the supplied username.
     *
     * @param username the username
     * @return the Authentication response
     */
    public AuthenticationResponse recoverPassword(String username, ProceedContext proceedContext) {
        try {
            boolean isIdentifyInOneStep = proceedContext.isIdentifyInOneStep();

            if (isIdentifyInOneStep) {
                // recover
                AuthenticationTransaction recoverTransaction = AuthenticationTransaction.proceed(client, proceedContext, () -> {
                    RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
                            .withStateHandle(proceedContext.getStateHandle())
                            .build();

                    return client.recover(recoverRequest, null);
                });

                RemediationOption remediationOption = recoverTransaction.getRemediationOption(RemediationType.IDENTIFY_RECOVERY);

                IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
                        .withIdentifier(username)
                        .withStateHandle(proceedContext.getStateHandle())
                        .build();

                // identify user
                return recoverTransaction.proceed(() ->
                        remediationOption.proceed(client, identifyRequest)
                ).asAuthenticationResponse(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION);
            } else {
                // identify user
                AuthenticationTransaction identifyTransaction = AuthenticationTransaction.proceed(client, proceedContext, () -> {
                    IdentifyRequest identifyRequest = IdentifyRequestBuilder.builder()
                            .withIdentifier(username)
                            .withStateHandle(proceedContext.getStateHandle())
                            .build();
                    return client.identify(identifyRequest, proceedContext.getHref());
                });
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

                AuthenticationTransaction recoverTransaction = identifyTransaction.proceed(() -> {
                    // recover password
                    RecoverRequest recoverRequest = RecoverRequestBuilder.builder()
                            .withStateHandle(proceedContext.getStateHandle())
                            .build();
                    return recover.proceed(client, recoverRequest);
                });

                return recoverTransaction.asAuthenticationResponse(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION);
            }
        } catch (ProcessingException e) {
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    /**
     * Register new user with the supplied user profile reference.
     *
     * @param proceedContext the ProceedContext
     * @param userProfile the user profile
     * @return the Authentication response
     */
    public AuthenticationResponse register(ProceedContext proceedContext,
                                           UserProfile userProfile) {
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
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    /**
     * Select authenticator of the supplied type.
     *
     * @param proceedContext the ProceedContext
     * @param authenticator the authenticator
     * @return the Authentication response
     */
    public AuthenticationResponse selectAuthenticator(ProceedContext proceedContext,
                                                      com.okta.idx.sdk.api.client.Authenticator authenticator) {
        try {
            return AuthenticationTransaction.proceed(client, proceedContext, () -> {
                Authenticator authenticatorRequest = new Authenticator();
                authenticatorRequest.setId(authenticator.getId());
                if (authenticator.hasNestedFactors() && authenticator.getFactors().size() == 1) {
                    com.okta.idx.sdk.api.client.Authenticator.Factor factor = authenticator.getFactors().get(0);
                    authenticatorRequest.setMethodType(factor.getMethod());
                    authenticatorRequest.setEnrollmentId(factor.getEnrollmentId());
                }
                ChallengeRequest request = ChallengeRequestBuilder.builder()
                        .withStateHandle(proceedContext.getStateHandle())
                        .withAuthenticator(authenticatorRequest)
                        .build();
                return client.challenge(request, proceedContext.getHref());
            }).asAuthenticationResponse();
        } catch (ProcessingException e) {
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    /**
     * Select authenticator of the supplied type.
     *
     * @param proceedContext the ProceedContext
     * @param factor the factor
     * @return the Authentication response
     */
    public AuthenticationResponse selectFactor(ProceedContext proceedContext,
                                               com.okta.idx.sdk.api.client.Authenticator.Factor factor) {
        try {
            return AuthenticationTransaction.proceed(client, proceedContext, () -> {
                Authenticator authenticator = new Authenticator();
                authenticator.setId(factor.getId());
                authenticator.setEnrollmentId(factor.getEnrollmentId());
                authenticator.setMethodType(factor.getMethod());
                ChallengeRequest request = ChallengeRequestBuilder.builder()
                        .withStateHandle(proceedContext.getStateHandle())
                        .withAuthenticator(authenticator)
                        .build();
                return client.challenge(request, proceedContext.getHref());
            }).asAuthenticationResponse();
        } catch (ProcessingException e) {
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    /**
     * Enroll authenticator of the supplied type.
     *
     * @param proceedContext the ProceedContext
     * @param factor the factor
     * @return the Authentication response
     */
    public AuthenticationResponse enrollAuthenticator(ProceedContext proceedContext,
                                                      com.okta.idx.sdk.api.client.Authenticator.Factor factor) {
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
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    /**
     * Verify Authenticator with the supplied authenticator options.
     *
     * @param proceedContext the ProceedContext
     * @param verifyAuthenticatorOptions the verify Authenticator options
     * @return the Authentication response
     */
    public AuthenticationResponse verifyAuthenticator(ProceedContext proceedContext,
                                                      VerifyAuthenticatorOptions verifyAuthenticatorOptions) {
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
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    /**
     * Submit phone authenticator enrollment with the provided phone number.
     *
     * @param proceedContext the ProceedContext
     * @param phone the phone number
     * @param factor factor
     * @return the Authentication response
     */
    public AuthenticationResponse submitPhoneAuthenticator(ProceedContext proceedContext,
                                                           String phone,
                                                           com.okta.idx.sdk.api.client.Authenticator.Factor factor) {
        try {
            Assert.notNull(proceedContext, "proceed context cannot be null");

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
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    /**
     * Skip optional authenticator enrollment.
     *
     * @param proceedContext the ProceedContext
     * @return the Authentication response
     */
    public AuthenticationResponse skipAuthenticatorEnrollment(ProceedContext proceedContext) {
        try {
            SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest =
                    SkipAuthenticatorEnrollmentRequestBuilder.builder()
                            .withStateHandle(proceedContext.getStateHandle())
                            .build();

            return AuthenticationTransaction.proceed(client, proceedContext, () ->
                    client.skip(skipAuthenticatorEnrollmentRequest, proceedContext.getSkipHref())
            ).asAuthenticationResponse(AuthenticationStatus.SKIP_COMPLETE);
        } catch (ProcessingException e) {
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    /**
     * Resend code.
     *
     * @param proceedContext the ProceedContext
     * @return the Authentication response
     */
    public AuthenticationResponse resend(ProceedContext proceedContext) {
        try {
            return AuthenticationTransaction.proceed(client, proceedContext, () -> {
                SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest =
                        SkipAuthenticatorEnrollmentRequestBuilder.builder()
                                .withStateHandle(proceedContext.getStateHandle())
                                .build();
                return client.skip(skipAuthenticatorEnrollmentRequest, proceedContext.getResendHref());
            }).asAuthenticationResponse();
        } catch (ProcessingException e) {
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    /**
     * Get IDX client context by calling the interact endpoint.
     * ClientContext reference contains the interaction handle and PKCE params.
     * <p>
     * This function can be used by the client applications to get a handle
     * of {@link IDXClientContext} which can be used to reenter/resume the flow.
     *
     * @return the idx client context
     * @throws ProcessingException if the backend interact API call fails
     */
    public IDXClientContext getClientContext() throws ProcessingException {

        try {
            return client.interact();
        } catch (ProcessingException e) {
            logger.error("Error occurred:", e);
            ErrorResponse errorResponse = e.getErrorResponse();
            logger.error("Error details: {}, {}", errorResponse.getError(), errorResponse.getErrorDescription());
            throw e;
        }
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
     * Introspect to get the current state of the authentication.
     * This is useful when doing social auth, and not getting back an interaction_code.
     *
     * @param clientContext the client context
     * @return a AuthenticationResponse with a status representing the current location in the authentnication flow.
     */
    public AuthenticationResponse introspect(IDXClientContext clientContext) {
        try {
            return AuthenticationTransaction.introspect(client, clientContext).asAuthenticationResponse();
        } catch (ProcessingException e) {
            return handleProcessingException(e);
        }
    }

    /**
     * Populate UI form values for signing up a new user.
     *
     * @param proceedContext the proceedContext
     * @return the authentication response
     */
    public AuthenticationResponse fetchSignUpFormValues(ProceedContext proceedContext) {
        AuthenticationResponse newUserRegistrationResponse = new AuthenticationResponse();

        try {
            Assert.notNull(proceedContext.getSelectProfileEnrollHref(), "Policy not configured.");

            // enroll new user
            AuthenticationTransaction enrollTransaction = AuthenticationTransaction.proceed(client, proceedContext, () -> {
                EnrollRequest enrollRequest = EnrollRequestBuilder.builder()
                        .withStateHandle(proceedContext.getStateHandle())
                        .build();
                return client.enroll(enrollRequest, proceedContext.getSelectProfileEnrollHref());
            });

            RemediationOption enrollProfileRemediationOption =
                    enrollTransaction.getRemediationOption(RemediationType.ENROLL_PROFILE);

            List<FormValue> enrollProfileFormValues = Arrays.stream(enrollProfileRemediationOption.form())
                    .filter(x -> "userProfile".equals(x.getName()))
                    .collect(Collectors.toList());

            newUserRegistrationResponse.setFormValues(enrollProfileFormValues);
            newUserRegistrationResponse.setProceedContext(enrollTransaction.createProceedContext());
            return newUserRegistrationResponse;
        } catch (ProcessingException e) {
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    // If app sign-on policy is set to "any 1 factor", the next remediation after identify is
    // select-authenticator-authenticate
    // Check if that's the case, and proceed to select password authenticator
    private AuthenticationTransaction selectPasswordAuthenticatorIfNeeded(AuthenticationTransaction authenticationTransaction)
            throws ProcessingException {
        // If remediation contains challenge-authenticator for passcode, we don't need to check SELECT_AUTHENTICATOR_AUTHENTICATE
        Optional<RemediationOption> challengeRemediationOptionOptional =
                authenticationTransaction.getOptionalRemediationOption(RemediationType.CHALLENGE_AUTHENTICATOR);

        if (challengeRemediationOptionOptional.isPresent()) {
            // proceed with password challenge
            return authenticationTransaction;
        }

        Optional<RemediationOption> remediationOptionOptional =
                authenticationTransaction.getOptionalRemediationOption(RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE);
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
     * Helper to check if we have optional authenticators to skip in current remediation step.
     *
     * @param proceedContext the ProceedContext
     * @return true if we have optional authenticators to skip; false otherwise.
     */
    public boolean isSkipAuthenticatorPresent(ProceedContext proceedContext) {
        return proceedContext.getSkipHref() != null;
    }

    public AuthenticationResponse begin() {
        try {
            return AuthenticationTransaction.create(client).asAuthenticationResponse();
        } catch (ProcessingException e) {
            return handleProcessingException(e);
        } catch (IllegalArgumentException e) {
            return handleIllegalArgumentException(e);
        }
    }

    public AuthenticationResponse fetchTokenWithInteractionCode(String issuer,
                                                                ProceedContext proceedContext,
                                                                String interactionCode) {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        try {
            TokenResponse tokenResponse =
                    client.token(ClientUtil.getNormalizedUri(issuer, "/v1/token"),
                            "interaction_code", interactionCode, proceedContext.getClientContext());
            authenticationResponse.setTokenResponse(tokenResponse);
        } catch (ProcessingException e) {
            return handleProcessingException(e);
        } catch (MalformedURLException e) {
            logger.error("Error occurred", e);
        }

        return authenticationResponse;
    }
}
