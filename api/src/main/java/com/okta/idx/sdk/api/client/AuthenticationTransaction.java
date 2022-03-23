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
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.AuthenticationStatus;
import com.okta.idx.sdk.api.model.CurrentAuthenticatorEnrollment;
import com.okta.idx.sdk.api.model.CurrentAuthenticatorEnrollmentValue;
import com.okta.idx.sdk.api.model.EmailTokenType;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.Idp;
import com.okta.idx.sdk.api.model.Options;
import com.okta.idx.sdk.api.model.OptionsForm
import com.okta.idx.sdk.api.model.PollInfo;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.model.RemediationType;
import com.okta.idx.sdk.api.response.AuthenticationResponse;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

final class AuthenticationTransaction {

    static AuthenticationTransaction create(IDXClient client) throws ProcessingException {
        return create(client, null, null);
    }

    static AuthenticationTransaction create(IDXClient client, String token, EmailTokenType tokenType) throws ProcessingException {
        IDXClientContext idxClientContext;

        if (token == null) {
            idxClientContext = client.interact();
        } else {
            Assert.notNull(tokenType, "token type may not be null");
            idxClientContext = client.interact(token, tokenType);
        }

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

    private static final Logger logger = LoggerFactory.getLogger(AuthenticationTransaction.class);

    private final IDXClient client;
    private final IDXClientContext clientContext;
    private final IDXResponse idxResponse;

    AuthenticationTransaction(IDXClient client, IDXClientContext clientContext, IDXResponse idxResponse) {
        this.client = client;
        this.clientContext = clientContext;
        this.idxResponse = idxResponse;
    }

    String getStateHandle() {
        return idxResponse.getStateHandle();
    }

    IDXResponse getResponse() {
        return idxResponse;
    }

    ProceedContext createProceedContext() {
        if (idxResponse == null || idxResponse.remediation() == null || idxResponse.remediation().remediationOptions() == null) {
            logger.error("ProceedContext is null");
            return null;
        }

        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        String href = remediationOptions[0].getHref();
        String refresh = remediationOptions[0].getRefresh();

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
                pollInfo = new PollInfo(pollRemediationOption.getHref(), pollRemediationOption.getRefresh());
            }
        } else if (idxResponse.getCurrentAuthenticator() != null &&
                idxResponse.getCurrentAuthenticator().getValue() != null) {
            if (idxResponse.getCurrentAuthenticator().getValue().getResend() != null) {
                resendHref = idxResponse.getCurrentAuthenticator().getValue().getResend().getHref();
            }
            if (idxResponse.getCurrentAuthenticator().getValue().getPoll() != null) {
                RemediationOption pollRemediationOption = idxResponse.getCurrentAuthenticator().getValue().getPoll();
                pollInfo = new PollInfo(pollRemediationOption.getHref(), pollRemediationOption.getRefresh());
            }
        }

        return new ProceedContext(clientContext, getStateHandle(), href, skipHref, isIdentifyInOneStep,
                selectProfileEnrollHref, resendHref, pollInfo, refresh);
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
        return Arrays.stream(idxResponse.remediation().remediationOptions())
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

        String firstRemediation = "";
        if (idxResponse.remediation() != null && idxResponse.remediation().remediationOptions().length > 0) {
            firstRemediation = idxResponse.remediation().remediationOptions()[0].getName();
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
        FormValue[] formValues = remediationOptionOptional.get().form();

        Optional<FormValue> credentialsFormValueOptional = Arrays.stream(formValues)
                .filter(x -> "credentials".equals(x.getName()))
                .findFirst();

        return credentialsFormValueOptional.isPresent();
    }

    private static void copyErrorMessages(IDXResponse idxResponse, AuthenticationResponse authenticationResponse) {
        if (idxResponse == null || idxResponse.getMessages() == null) {
            return;
        }
        Arrays.stream(idxResponse.getMessages().getValue())
                .forEach(msg -> authenticationResponse.addError(msg.getMessage()));
    }

    private void fillOutAuthenticators(AuthenticationResponse authenticationResponse) {
        if (idxResponse == null || idxResponse.remediation() == null) {
            return;
        }
        RemediationOption[] remediationOptions = idxResponse.remediation().remediationOptions();
        if (remediationOptions.length > 0) {
            // We only care about the first remediation.
            fillOutAuthenticators(remediationOptions[0], authenticationResponse);
        }
    }

    private void fillOutIdps(AuthenticationResponse authenticationResponse) {
        if (idxResponse == null || idxResponse.remediation() == null) {
            return;
        }

        List<Idp> idpList = new LinkedList<>();

        RemediationOption[] remediationOptions = this.getResponse().remediation().remediationOptions();

        List<RemediationOption> remediationOptionList = Arrays.stream(remediationOptions)
                .filter(x -> "redirect-idps".equals(x.getName()) || "redirect-idp".equals(x.getName()))
                .collect(Collectors.toList());

        for (RemediationOption remediationOption : remediationOptionList) {
            idpList.add(new Idp(remediationOption.getType(), remediationOption.getHref()));
        }

        authenticationResponse.setIdps(idpList);
    }

    private void fillOutAuthenticators(RemediationOption remediationOption, AuthenticationResponse authenticationResponse) {
        if (remediationOption != null) {
            FormValue[] formValues = remediationOption.form();

            if (formValues != null) {
                Optional<FormValue> formValueOptional = Arrays.stream(formValues)
                        .filter(x -> "authenticator".equals(x.getName()))
                        .findFirst();

                if (formValueOptional.isPresent()) {
                    Options[] options = formValueOptional.get().options();

                    List<Authenticator> authenticators = getAuthenticators(options);
                    if (authenticators == null) {
                        authenticators = getAuthenticators(formValueOptional.get());
                    }

                    authenticationResponse.setAuthenticators(authenticators);
                }
            }
        }
    }

    private List<Authenticator> getAuthenticators(Options[] options) {
        if (options == null || options.length == 0) {
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

            FormValue[] optionFormValues = ((OptionsForm) option.getValue()).getForm().getValue();
            for (FormValue formValue : optionFormValues) {
                if (formValue.getName().equals("methodType")) {
                    authenticatorType = String.valueOf(formValue.getValue());
                    // parse value from children
                    Options[] nestedOptions = formValue.options();
                    if (nestedOptions.length > 0) {
                        for (Options children : nestedOptions) {
                            nestedMethods.put(String.valueOf(children.getValue()), String.valueOf(children.getLabel()));
                        }
                        hasNestedFactors = true;
                    } else {
                        nestedMethods.put(String.valueOf(formValue.getValue()), label);
                    }
                } else if ("channel".equals(formValue.getName())) {
                    authenticatorType = String.valueOf(option.getLabel())
                            .toLowerCase(Locale.ROOT).replaceAll(" ", "_");
                    isChannelFactor = true;
                    Options[] nestedOptions = formValue.options();
                    if (nestedOptions.length > 0) {
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
                Options[] nestedOptions = formValue.options();
                if (nestedOptions.length > 0) {
                    for (Options children : nestedOptions) {
                        nestedMethods.put(String.valueOf(children.getValue()), String.valueOf(children.getLabel()));
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
