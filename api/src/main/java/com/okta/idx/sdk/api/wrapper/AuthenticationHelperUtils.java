package com.okta.idx.sdk.api.wrapper;

import com.okta.commons.lang.Assert;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.Authenticator;
import com.okta.idx.sdk.api.model.Credentials;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.MessageValue;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.request.AnswerChallengeRequest;
import com.okta.idx.sdk.api.request.AnswerChallengeRequestBuilder;
import com.okta.idx.sdk.api.request.ChallengeRequest;
import com.okta.idx.sdk.api.request.ChallengeRequestBuilder;
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
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

public class AuthenticationHelperUtils {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationHelperUtils.class);

    /**
     * Authenticate user with username and password by completing the password authenticator
     * challenge and returns the Token (access_token/id_token/refresh_token).
     *
     * Note: This requires 'Password' as the ONLY required factor in app Sign-on policy configuration.
     *
     * @param client the IDX Client reference
     * @param clientContext the IDX Client context
     * @param username the email
     * @param password the password
     * @return the authentication response
     */
    public static AuthenticationResponse authenticate(IDXClient client, IDXClientContext clientContext, String username, String password) {

        AuthenticationResponse authenticationResponse = new AuthenticationResponse();

        TokenResponse tokenResponse = new TokenResponse();

        try {
            IDXResponse idxResponse = client.introspect(clientContext);
            String stateHandle = idxResponse.getStateHandle();
            Assert.hasText(stateHandle, "Missing state handle");

            // check remediation options to continue the flow
            RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();

            logger.info("Remediation Options: {}", Arrays.stream(remediationOptions)
                    .map(RemediationOption::getName)
                    .collect(Collectors.toList()));

            Optional<RemediationOption> remediationOptionsOptional = Arrays.stream(remediationOptions)
                    .findFirst();
            Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation options");

            RemediationOption remediationOption = remediationOptionsOptional.get();
            FormValue[] formValues = remediationOption.form();

            // check if credentials are required to move on to next step
            Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                    .filter(x -> "credentials".equals(x.getName()))
                    .findFirst();

            IdentifyRequest identifyRequest = null;

            if (credentialsFormValueOptional.isPresent()) {
                FormValue credentialsFormValue = credentialsFormValueOptional.get();

                // check if password credential is required to be sent in identify user step
                if (credentialsFormValue.isRequired()) {
                    Credentials credentials = new Credentials();
                    credentials.setPasscode(password.toCharArray());

                    identifyRequest = (IdentifyRequestBuilder.builder()
                            .withIdentifier(username)
                            .withCredentials(credentials)
                            .withStateHandle(stateHandle)
                            .build());
                }
            } else {
                // password credential is not necessary, so sending just the identifier (username)
                identifyRequest = (IdentifyRequestBuilder.builder()
                        .withIdentifier(username)
                        .withStateHandle(stateHandle)
                        .build());
            }

            // identify user
            idxResponse = remediationOption.proceed(client, identifyRequest);

            if (idxResponse.isLoginSuccessful()) {
                logger.info("Login Successful!");
                tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, clientContext);
            } else if (idxResponse.getMessages() != null && idxResponse.remediation() == null) {
                authenticationResponse.addError("Terminal error occurred");
                Arrays.stream(idxResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
            } else {
                logger.info("Attempting to follow next remediation option(s)");

                // we need to follow remediation steps
                remediationOptions = idxResponse.remediation().remediationOptions();

                logger.info("Remediation Options: {}", Arrays.stream(remediationOptions)
                        .map(RemediationOption::getName)
                        .collect(Collectors.toList()));

                remediationOptionsOptional = Arrays.stream(remediationOptions)
                        .filter(x -> "select-authenticator-authenticate".equals(x.getName()))
                        .findFirst();
                remediationOption = remediationOptionsOptional.get();

                // get authenticator options
                Map<String, String> authenticatorOptions = remediationOption.getAuthenticatorOptions();
                logger.info("Authenticator Options: {}", authenticatorOptions);

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

                logger.info("Remediation Options: {}", Arrays.stream(remediationOptions)
                        .map(RemediationOption::getName)
                        .collect(Collectors.toList()));

                remediationOptionsOptional = Arrays.stream(remediationOptions)
                        .filter(x -> "challenge-authenticator".equals(x.getName()))
                        .findFirst();

                Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing challenge-authenticator remediation option");

                remediationOption = remediationOptionsOptional.get();

                // answer password authenticator challenge
                Credentials credentials = new Credentials();
                credentials.setPasscode(password.toCharArray());

                // build answer password authenticator challenge request
                AnswerChallengeRequest passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                        .withStateHandle(stateHandle)
                        .withCredentials(credentials)
                        .build();
                idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

                if (idxResponse.isLoginSuccessful()) {
                    logger.info("Login Successful!");
                    tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, clientContext);
                } else if (idxResponse.getMessages() != null && idxResponse.remediation() == null) {
                    logger.error("Terminal error occurred");
                    Arrays.stream(idxResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                } else {
                    // password expired or required to be changed on initial login

                    remediationOptions = idxResponse.remediation().remediationOptions();

                    logger.info("Remediation Options: {}", Arrays.stream(remediationOptions)
                            .map(RemediationOption::getName)
                            .collect(Collectors.toList()));

                    remediationOptionsOptional = Arrays.stream(remediationOptions)
                            .filter(x -> "reenroll-authenticator".equals(x.getName()))
                            .findFirst();

                    remediationOption = remediationOptionsOptional.get();

                    // set new password
                    credentials.setPasscode("newAbcd1234".toCharArray());

                    // build answer password authenticator challenge request
                    passwordAuthenticatorAnswerChallengeRequest = AnswerChallengeRequestBuilder.builder()
                            .withStateHandle(stateHandle)
                            .withCredentials(credentials)
                            .build();

                    idxResponse = remediationOption.proceed(client, passwordAuthenticatorAnswerChallengeRequest);

                    if (idxResponse.isLoginSuccessful()) {
                        logger.info("Login Successful!");
                        tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, clientContext);
                        logger.info("Token RESPONSE! {}", tokenResponse);
                    } else if (idxResponse.getMessages() != null && idxResponse.remediation() == null) {
                        logger.error("Terminal error occurred");
                        Arrays.stream(idxResponse.getMessages().getValue()).forEach(msg -> authenticationResponse.addError(msg.getMessage()));
                    } else {
                        authenticationResponse.addError("Could not authenticate user with password factor alone. Please review your app Sign-on policy configuration.");
                    }
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

        authenticationResponse.setTokenResponse(tokenResponse);
        return authenticationResponse;
    }

}
