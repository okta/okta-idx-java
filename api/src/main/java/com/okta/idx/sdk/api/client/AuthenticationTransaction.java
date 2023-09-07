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

import com.okta.commons.http.Response;
import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Collections;
import com.okta.commons.lang.Strings;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.CurrentAuthenticatorEnrollment;
import com.okta.idx.sdk.api.model.CurrentAuthenticatorEnrollmentValue;
import com.okta.idx.sdk.api.model.RequestContext;
import com.okta.idx.sdk.api.model.EmailTokenType;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.Idp;
import com.okta.idx.sdk.api.model.Options;
import com.okta.idx.sdk.api.model.OptionsForm;
import com.okta.idx.sdk.api.model.PollInfo;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.RemediationType;
import com.okta.idx.sdk.api.model.SecurityQuestion;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

final class AuthenticationTransaction {

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationTransaction.class);

    private final IDXClient client;
    private final IDXClientContext clientContext;
    private final IDXResponse idxResponse;

    static AuthenticationTransaction create(IDXClient client) throws ProcessingException {
        return create(client, null, null, null);
    }

    static AuthenticationTransaction create(IDXClient client, RequestContext requestContext) throws ProcessingException {
        return create(client, null, null, requestContext);
    }

    AuthenticationTransaction(IDXClient client, IDXClientContext clientContext, IDXResponse idxResponse) {
        this.client = client;
        this.clientContext = clientContext;
        this.idxResponse = idxResponse;
    }

    static AuthenticationTransaction create(IDXClient client,
                                            String token,
                                            EmailTokenType tokenType,
                                            RequestContext requestContext) throws ProcessingException {

        IDXClientContext idxClientContext = client.interact(token, tokenType, requestContext);
        Assert.notNull(idxClientContext, "IDX client context may not be null");

        IDXResponse introspectResponse = client.introspect(idxClientContext);

        String stateHandle = introspectResponse.getStateHandle();
        Assert.hasText(stateHandle, "State handle may not be null");

        WrapperUtil.printRemediationOptions(introspectResponse);

        return new AuthenticationTransaction(client, idxClientContext, introspectResponse);
    }

    static AuthenticationTransaction introspect(IDXClient client, IDXClientContext clientContext) throws ProcessingException {
        IDXResponse introspectResponse = client.introspect(clientContext);

        WrapperUtil.printRemediationOptions(introspectResponse);

        return new AuthenticationTransaction(client, clientContext, introspectResponse);
    }

    static AuthenticationTransaction proceed(IDXClient client, ProceedContext proceedContext, Factory factory) throws ProcessingException {
        IDXResponse idxResponse = factory.create();
        WrapperUtil.printRemediationOptions(idxResponse);
        WrapperUtil.printMessage(idxResponse);
        return new AuthenticationTransaction(client, proceedContext.getClientContext(), idxResponse);
    }

    static Response verifyEmailToken(IDXClient client, String token) throws ProcessingException {
        return client.verifyEmailToken(token);
    }

    interface Factory {
        IDXResponse create() throws ProcessingException;
    }

    String getStateHandle() {
        return idxResponse.getStateHandle();
    }

    IDXResponse getResponse() {
        return idxResponse;
    }

    ProceedContext createProceedContext() {
        if (idxResponse == null || idxResponse.remediation() == null || idxResponse.remediation().remediationOptions() == null) {
            return null;
        }

        List<RemediationOption> remediationOptions = idxResponse.remediation().remediationOptions();
        String href = remediationOptions.get(0).getHref();
        String refresh = remediationOptions.get(0).getRefresh();

        String skipHref = null;
        Optional<RemediationOption> skipOptional = getOptionalRemediationOption(RemediationType.SKIP);
        if (skipOptional.isPresent()) {
            skipHref = skipOptional.get().getHref();
        }

        boolean isIdentifyInOneStep = isRemediationRequireCredentials(RemediationType.IDENTIFY);

        String selectProfileEnrollHref = null;
        Optional<RemediationOption> selectEnrollProfileRemediationOption =
                getOptionalRemediationOption(RemediationType.SELECT_ENROLL_PROFILE);
        if (selectEnrollProfileRemediationOption.isPresent()) {
            selectProfileEnrollHref = selectEnrollProfileRemediationOption.get().getHref();
        }

        String resendHref = null;
        PollInfo pollInfo = null;

        if (idxResponse.getCurrentAuthenticatorEnrollment() != null &&
                idxResponse.getCurrentAuthenticatorEnrollment().getValue() != null) {
            if (idxResponse.getCurrentAuthenticatorEnrollment().getValue().getResend() != null) {
                resendHref = idxResponse.getCurrentAuthenticatorEnrollment().getValue().getResend().getHref();
            }
            if (idxResponse.getCurrentAuthenticatorEnrollment().getValue().getPoll() != null) {
                RemediationOption pollRemediationOption = idxResponse.getCurrentAuthenticatorEnrollment().getValue().getPoll();
                pollInfo = new PollInfo(pollRemediationOption.getHref(), Duration.ofMillis(Long.parseLong(pollRemediationOption.getRefresh())));
            }
        } else if (idxResponse.getCurrentAuthenticator() != null &&
                idxResponse.getCurrentAuthenticator().getValue() != null) {
            if (idxResponse.getCurrentAuthenticator().getValue().getResend() != null) {
                resendHref = idxResponse.getCurrentAuthenticator().getValue().getResend().getHref();
            }
            if (idxResponse.getCurrentAuthenticator().getValue().getPoll() != null) {
                RemediationOption pollRemediationOption = idxResponse.getCurrentAuthenticator().getValue().getPoll();
                pollInfo = new PollInfo(pollRemediationOption.getHref(), Duration.ofMillis(Long.parseLong(pollRemediationOption.getRefresh())));
            }
        }

        return new ProceedContext(clientContext, getStateHandle(), href, skipHref, isIdentifyInOneStep,
                selectProfileEnrollHref, resendHref, pollInfo, refresh, idxResponse);
    }

    RemediationOption getRemediationOption(String name) {
        Optional<RemediationOption> remediationOptionsOptional = getOptionalRemediationOption(name);
        Assert.isTrue(remediationOptionsOptional.isPresent(), "Missing remediation option " + name);
        return remediationOptionsOptional.get();
    }

    Optional<RemediationOption> getOptionalRemediationOption(String name) {
        if (idxResponse == null || idxResponse.remediation() == null) {
            return Optional.empty();
        }
        return idxResponse.remediation().remediationOptions().stream()
                .filter(x -> name.equals(x.getName()))
                .findFirst();
    }

    AuthenticationTransaction proceed(Factory factory) throws ProcessingException {
        IDXResponse idxResponse = factory.create();
        WrapperUtil.printRemediationOptions(idxResponse);
        WrapperUtil.printMessage(idxResponse);
        return new AuthenticationTransaction(client, clientContext, idxResponse);
    }

    AuthenticationResponse asAuthenticationResponse() throws ProcessingException {
        return asAuthenticationResponse(AuthenticationStatus.UNKNOWN);
    }

    AuthenticationResponse asAuthenticationResponse(AuthenticationStatus defaultStatus) throws ProcessingException {
        AuthenticationResponse authenticationResponse = new AuthenticationResponse();
        authenticationResponse.setProceedContext(createProceedContext());

        copyErrorMessages(idxResponse, authenticationResponse);

        fillOutIdps(authenticationResponse);
        fillOutAuthenticators(authenticationResponse);

        if (idxResponse == null) {
            return authenticationResponse;
        }

        if (idxResponse.isLoginSuccessful()) {
            // login successful
            logger.info("Login Successful!");
            TokenResponse tokenResponse = idxResponse.getSuccessWithInteractionCode().exchangeCode(client, clientContext);
            authenticationResponse.setAuthenticationStatus(AuthenticationStatus.SUCCESS);
            authenticationResponse.setTokenResponse(tokenResponse);
            return authenticationResponse;
        }

        if (idxResponse.getCurrentAuthenticator() != null) {
            authenticationResponse.getWebAuthnParams().setCurrentAuthenticator(idxResponse.getCurrentAuthenticator());
        }

        if (idxResponse.getCurrentAuthenticatorEnrollment() != null) {
            authenticationResponse.setCurrentAuthenticatorEnrollment(idxResponse.getCurrentAuthenticatorEnrollment());
        }

        if (idxResponse.getAuthenticatorEnrollments() != null) {
            authenticationResponse.setAuthenticatorEnrollments(idxResponse.getAuthenticatorEnrollments());
        }

        if (idxResponse.getUser() != null) {
            authenticationResponse.setUser(idxResponse.getUser());
        }

        String firstRemediation = "";
        if (idxResponse.remediation() != null && idxResponse.remediation().remediationOptions().size() > 0) {
            firstRemediation = idxResponse.remediation().remediationOptions().get(0).getName();
        }

        switch (firstRemediation) {
            case RemediationType.REENROLL_AUTHENTICATOR:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.PASSWORD_EXPIRED);
                break;
            case RemediationType.AUTHENTICATOR_VERIFICATION_DATA:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION_DATA);
                break;
            case RemediationType.AUTHENTICATOR_ENROLLMENT_DATA:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_DATA);
                break;
            case RemediationType.CHALLENGE_AUTHENTICATOR:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_AUTHENTICATOR_VERIFICATION);
                break;
            case RemediationType.SELECT_AUTHENTICATOR_AUTHENTICATE:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_AUTHENTICATOR_SELECTION);
                break;
            case RemediationType.SELECT_AUTHENTICATOR_ENROLL:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT_SELECTION);
                break;
            case RemediationType.ENROLL_PROFILE:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_PROFILE_ENROLLMENT);
                break;
            case RemediationType.ENROLL_AUTHENTICATOR:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_AUTHENTICATOR_ENROLLMENT);
                break;
            case RemediationType.ENROLL_POLL:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_POLL_ENROLLMENT);
                break;
            case RemediationType.ENROLLMENT_CHANNEL_DATA:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_CHANNEL_DATA_ENROLLMENT);
                break;
            case RemediationType.CHALLENGE_POLL:
                authenticationResponse.setAuthenticationStatus(AuthenticationStatus.AWAITING_CHALLENGE_POLL);
                break;
            default:
                authenticationResponse.setAuthenticationStatus(defaultStatus);
                break;
        }

        Optional.ofNullable(idxResponse.getCurrentAuthenticator())
                .map(CurrentAuthenticatorEnrollment::getValue)
                .map(CurrentAuthenticatorEnrollmentValue::getContextualData)
                .ifPresent(authenticationResponse::setContextualData);
        return authenticationResponse;
    }

    boolean isRemediationRequireCredentials(String name) {
        if (idxResponse.remediation() == null) {
            return false;
        }

        Optional<RemediationOption> remediationOptionOptional = getOptionalRemediationOption(name);
        if (!remediationOptionOptional.isPresent()) {
            return false;
        }
        List<FormValue> formValues = remediationOptionOptional.get().form();

        Optional<FormValue> credentialsFormValueOptional = formValues.stream()
                .filter(x -> "credentials".equals(x.getName()))
                .findFirst();

        return credentialsFormValueOptional.isPresent();
    }

    private static void copyErrorMessages(IDXResponse idxResponse, AuthenticationResponse authenticationResponse) {
        if (idxResponse == null || idxResponse.getMessages() == null) {
            return;
        }
        idxResponse.getMessages().getValue().stream()
                .forEach(msg -> {
                    String message = msg.getMessage();
                    if (msg.getI18NMessage() != null && Strings.hasText(msg.getI18NMessage().getKey())) {
                        message += ", " + msg.getI18NMessage();
                    }
                    authenticationResponse.addError(message);
                });
    }

    private void fillOutAuthenticators(AuthenticationResponse authenticationResponse) {
        if (idxResponse == null || idxResponse.remediation() == null) {
            return;
        }
        List<RemediationOption> remediationOptions = idxResponse.remediation().remediationOptions();
        if (!Collections.isEmpty(remediationOptions)) {
            // We only care about the first remediation.
            fillOutAuthenticators(remediationOptions.get(0), authenticationResponse);
        }
    }

    private void fillOutIdps(AuthenticationResponse authenticationResponse) {
        if (idxResponse == null || idxResponse.remediation() == null) {
            return;
        }

        List<Idp> idpList = new LinkedList<>();

        List<RemediationOption> remediationOptions = this.getResponse().remediation().remediationOptions();

        List<RemediationOption> remediationOptionList = remediationOptions.stream()
                .filter(x -> "redirect-idps".equals(x.getName()) || "redirect-idp".equals(x.getName()))
                .collect(Collectors.toList());

        for (RemediationOption remediationOption : remediationOptionList) {
            idpList.add(new Idp(remediationOption.getType(), remediationOption.getHref()));
        }

        authenticationResponse.setIdps(idpList);
    }

    private void fillOutAuthenticators(RemediationOption remediationOption, AuthenticationResponse authenticationResponse) {
        if (remediationOption != null) {
            List<FormValue> formValues = remediationOption.form();
            if (formValues != null) {
                Optional<FormValue> formValueOptional = formValues.stream()
                        .filter(x -> "authenticator".equals(x.getName()))
                        .findFirst();

                if (formValueOptional.isPresent()) {
                    List<Options> options = formValueOptional.get().options();

                    List<Authenticator> authenticators = getAuthenticators(options);
                    if (authenticators == null) {
                        authenticators = getAuthenticators(formValueOptional.get());
                    }

                    authenticationResponse.setAuthenticators(authenticators);
                } else {
                    formValueOptional = formValues.stream()
                            .filter(x -> "credentials".equals(x.getName()))
                            .findFirst();

                    if (formValueOptional.isPresent()) {
                        List<Options> options = formValueOptional.get().options();

                        if (options != null) {
                            boolean isSecQnAuth = options.stream().anyMatch(x -> "Choose a security question".equals(x.getLabel()));

                            if (isSecQnAuth) {
                                List<SecurityQuestion> securityQuestions = getSecurityQuestions(options);
                                if (securityQuestions != null) {
                                    authenticationResponse.setSecurityQuestions(securityQuestions);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private List<SecurityQuestion> getSecurityQuestions(List<Options> options) {
        if (Collections.isEmpty(options)) {
            return null;
        }

        List<SecurityQuestion> securityQuestions = new ArrayList<>();

        for (Options option : options) {
            List<FormValue> optionFormValues = ((OptionsForm) option.getValue()).getForm().getValue();
            for (FormValue formValue : optionFormValues) {
                if (formValue.options() != null) {
                    formValue.options().stream().forEach(e -> securityQuestions.add(new SecurityQuestion(e.getLabel(), String.valueOf(e.getValue()))));
                }
            }
        }

        return securityQuestions;
    }

    private List<Authenticator> getAuthenticators(List<Options> options) {
        if (Collections.isEmpty(options)) {
            return null;
        }
        List<Authenticator> authenticators = new ArrayList<>();

        for (Options option : options) {
            String id = null;
            String label = option.getLabel();
            String enrollmentId = null;
            String authenticatorType = null;
            boolean hasNestedFactors = false;
            boolean isChannelFactor = false;
            Map<String, String> nestedMethods = new LinkedHashMap<>();

            List<FormValue> optionFormValues = ((OptionsForm) option.getValue()).getForm().getValue();
            for (FormValue formValue : optionFormValues) {
                if (formValue.getName().equals("methodType")) {
                    authenticatorType = String.valueOf(formValue.getValue());
                    // parse value from children
                    List<Options> nestedOptions = formValue.options();
                    if (nestedOptions.size() > 0) {
                        for (Options children : nestedOptions) {
                            nestedMethods.put(String.valueOf(children.getValue()), String.valueOf(children.getLabel()));
                            authenticatorType = String.valueOf(option.getLabel()).toLowerCase(Locale.ROOT);
                        }
                        hasNestedFactors = true;
                    } else {
                        nestedMethods.put(String.valueOf(formValue.getValue()), label);
                    }
                } else if ("channel".equals(formValue.getName())) {
                    authenticatorType = String.valueOf(option.getLabel())
                            .toLowerCase(Locale.ROOT).replaceAll(" ", "_");
                    isChannelFactor = true;
                    List<Options> nestedOptions = formValue.options();
                    if (nestedOptions.size() > 0) {
                        for (Options children : nestedOptions) {
                            nestedMethods.put(String.valueOf(children.getValue()), String.valueOf(children.getLabel()));
                        }
                        hasNestedFactors = true;
                    } else {
                        nestedMethods.put(authenticatorType, label);
                    }
                }
                if (formValue.getName().equals("id")) {
                    id = String.valueOf(formValue.getValue());
                }
                if (formValue.getName().equals("enrollmentId")) {
                    enrollmentId = String.valueOf(formValue.getValue());
                }
            }

            List<Authenticator.Factor> factors = new ArrayList<>();
            for (Map.Entry<String, String> entry : nestedMethods.entrySet()) {
                factors.add(new Authenticator.Factor(
                        id, entry.getKey(), enrollmentId, entry.getValue(), isChannelFactor ? entry.getKey() : null)
                );
            }
            authenticators.add(new Authenticator(id, authenticatorType, label, factors, hasNestedFactors));
        }
        return authenticators;
    }

    private List<Authenticator> getAuthenticators(FormValue parent) {
        if (parent == null) {
            return null;
        }
        List<Authenticator> authenticators = new ArrayList<>();

        String id = null;
        String label = parent.getLabel();
        String enrollmentId = null;
        String authenticatorType = null;
        Map<String, String> nestedMethods = new LinkedHashMap<>();
        boolean hasNestedFactors = false;

        for (FormValue formValue : parent.form().getValue()) {
            if (formValue.getName().equals("methodType")) {
                authenticatorType = String.valueOf(formValue.getValue());
                // parse value from children
                List<Options> nestedOptions = formValue.options();
                if (nestedOptions.size() > 0) {
                    for (Options children : nestedOptions) {
                        nestedMethods.put(String.valueOf(children.getValue()), String.valueOf(children.getLabel()));
                        authenticatorType = label.toLowerCase(Locale.ROOT);
                    }
                    hasNestedFactors = true;
                } else {
                    nestedMethods.put(String.valueOf(formValue.getValue()), label);
                }
            }
            if (formValue.getName().equals("id")) {
                id = String.valueOf(formValue.getValue());
            }
            if (formValue.getName().equals("enrollmentId")) {
                enrollmentId = String.valueOf(formValue.getValue());
            }
        }

        List<Authenticator.Factor> factors = new ArrayList<>();
        for (Map.Entry<String, String> entry : nestedMethods.entrySet()) {
            factors.add(new Authenticator.Factor(id, entry.getKey(), enrollmentId, entry.getValue(), null));
        }
        authenticators.add(new Authenticator(id, authenticatorType, label, factors, hasNestedFactors));

        return authenticators;
    }
}
