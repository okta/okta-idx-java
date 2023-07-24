/*
 * Copyright (c) 2020-Present, Okta, Inc.
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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.okta.commons.http.DefaultRequest;
import com.okta.commons.http.HttpException;
import com.okta.commons.http.HttpHeaders;
import com.okta.commons.http.HttpMethod;
import com.okta.commons.http.Request;
import com.okta.commons.http.RequestExecutor;
import com.okta.commons.http.RequestExecutorFactory;
import com.okta.commons.http.Response;
import com.okta.commons.http.authc.DisabledAuthenticator;
import com.okta.commons.http.config.HttpClientConfiguration;
import com.okta.commons.lang.ApplicationInfo;
import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Classes;
import com.okta.commons.lang.Strings;
import com.okta.idx.sdk.api.config.ClientConfiguration;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.model.RequestContext;
import com.okta.idx.sdk.api.model.EmailTokenType;
import com.okta.idx.sdk.api.model.FormValue;
import com.okta.idx.sdk.api.model.IDXClientContext;
import com.okta.idx.sdk.api.model.RemediationOption;
import com.okta.idx.sdk.api.request.AnswerChallengeRequest;
import com.okta.idx.sdk.api.request.CancelRequest;
import com.okta.idx.sdk.api.request.CancelRequestBuilder;
import com.okta.idx.sdk.api.request.ChallengeRequest;
import com.okta.idx.sdk.api.request.EnrollRequest;
import com.okta.idx.sdk.api.request.EnrollUserProfileUpdateRequest;
import com.okta.idx.sdk.api.request.IdentifyRequest;
import com.okta.idx.sdk.api.request.IntrospectRequest;
import com.okta.idx.sdk.api.request.PollRequest;
import com.okta.idx.sdk.api.request.RecoverRequest;
import com.okta.idx.sdk.api.request.SkipAuthenticatorEnrollmentRequest;
import com.okta.idx.sdk.api.response.ErrorResponse;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.InteractResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import com.okta.idx.sdk.api.util.PkceUtil;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.UUID;
import java.util.stream.Collectors;

import static com.okta.idx.sdk.api.util.ClientUtil.normalizedIssuerUri;

final class BaseIDXClient implements IDXClient {

    private final ClientConfiguration clientConfiguration;

    private final ObjectMapper objectMapper;
    private final RequestExecutor requestExecutor;

    public BaseIDXClient(ClientConfiguration clientConfiguration, RequestExecutor requestExecutor) {

        this.clientConfiguration = clientConfiguration;

        this.objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

        HttpClientConfiguration httpClientConfiguration = new HttpClientConfiguration();
        httpClientConfiguration.setBaseUrl(clientConfiguration.getBaseUrl());
        httpClientConfiguration.setRequestAuthenticator(new DisabledAuthenticator());

        if (requestExecutor != null) {
            this.requestExecutor = requestExecutor;
        } else {
            String msg = "Unable to find a '" + RequestExecutorFactory.class.getName() + "' " + "implementation on the classpath.";
            this.requestExecutor = Classes.loadFromService(RequestExecutorFactory.class, msg).create(httpClientConfiguration);
        }
    }

    @Override
    public IDXClientContext interact() throws ProcessingException {
        return interact(null, null, null);
    }

    @Override
    public IDXClientContext interact(String token, EmailTokenType tokenType, RequestContext requestContext) throws ProcessingException {

        InteractResponse interactResponse;
        String codeVerifier, codeChallenge, state;

        try {
            codeVerifier = PkceUtil.generateCodeVerifier();
            codeChallenge = PkceUtil.generateCodeChallenge(codeVerifier);
            state = UUID.randomUUID().toString();

            StringBuilder urlParameters = new StringBuilder()
                .append("client_id=").append(clientConfiguration.getClientId())
                .append("&client_secret=").append(clientConfiguration.getClientSecret())
                .append("&scope=").append(clientConfiguration.getScopes().stream()
                    .map(Object::toString).collect(Collectors.joining(" ")))
                .append("&code_challenge=").append(codeChallenge)
                .append("&code_challenge_method=").append(PkceUtil.CODE_CHALLENGE_METHOD)
                .append("&redirect_uri=").append(clientConfiguration.getRedirectUri())
                .append("&state=").append(state);
            if (Strings.hasText(token) && !Strings.isEmpty(tokenType)) {
                if (tokenType == EmailTokenType.ACTIVATION_TOKEN) {
                    urlParameters.append("&activation_token=").append(token);
                } else if (tokenType == EmailTokenType.RECOVERY_TOKEN) {
                    urlParameters.append("&recovery_token=").append(token);
                }
            }

            HttpHeaders httpHeaders = getHttpHeaders(true);

            // include additional headers (for interact endpoint only), if present in request context.
            if (requestContext != null) {
                if (Strings.hasText(requestContext.getUserAgent())) {
                    httpHeaders.set(RequestContext.X_OKTA_USER_AGENT_EXTENDED,
                            requestContext.getUserAgent());
                }

                // set 'X-Forwarded-For' & 'X-Device-Token' headers for confidential clients only,
                // these headers will be ignored for non-confidential clients.
                if (Strings.hasText(clientConfiguration.getClientSecret())) {
                    if (Strings.hasText(requestContext.getDeviceToken())) {
                        httpHeaders.set(RequestContext.X_DEVICE_TOKEN,
                                requestContext.getDeviceToken());
                    }
                    if (Strings.hasText(requestContext.getIpAddress())) {
                        httpHeaders.set(RequestContext.X_FORWARDED_FOR,
                                requestContext.getIpAddress());
                    }
                }
            }

            Request request = new DefaultRequest(
                HttpMethod.POST,
                normalizedIssuerUri(clientConfiguration.getIssuer(), "/v1/interact"),
                null,
                httpHeaders,
                new ByteArrayInputStream(urlParameters.toString().getBytes(StandardCharsets.UTF_8)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            interactResponse = objectMapper.convertValue(responseJsonNode, InteractResponse.class);

            Assert.notNull(interactResponse, "interact response cannot be null");
            Assert.notNull(interactResponse.getInteractionHandle(), "interactionHandle cannot be null");

        } catch (IOException | IllegalArgumentException | HttpException | NoSuchAlgorithmException e) {
            throw new ProcessingException(e);
        }

        return new IDXClientContext(codeVerifier, codeChallenge, interactResponse.getInteractionHandle(), state);
    }

    @Override
    public IDXResponse introspect(IDXClientContext idxClientContext) throws ProcessingException {

        IDXResponse idxResponse;

        IntrospectRequest introspectRequest = new IntrospectRequest(idxClientContext.getInteractionHandle());

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                clientConfiguration.getBaseUrl() + "/idp/idx/introspect",
                null,
                getHttpHeaders(false),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(introspectRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            idxResponse = objectMapper.convertValue(responseJsonNode, IDXResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return idxResponse;
    }

    @Override
    public IDXResponse identify(IdentifyRequest identifyRequest, String href) throws ProcessingException {

        IDXResponse idxResponse;

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                href,
                null,
                getHttpHeaders(false),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(identifyRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            idxResponse = objectMapper.convertValue(responseJsonNode, IDXResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return idxResponse;
    }

    @Override
    public IDXResponse enroll(EnrollRequest enrollRequest, String href) throws ProcessingException {

        IDXResponse idxResponse;

        Assert.notNull(href, "href cannot be null");

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                href,
                null,
                getHttpHeaders(false),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(enrollRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            idxResponse = objectMapper.convertValue(responseJsonNode, IDXResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return idxResponse;
    }

    @Override
    public IDXResponse challenge(ChallengeRequest challengeRequest, String href) throws ProcessingException {

        IDXResponse idxResponse;

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                href,
                null,
                getHttpHeaders(false),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(challengeRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            idxResponse = objectMapper.convertValue(responseJsonNode, IDXResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return idxResponse;
    }

    @Override
    public IDXResponse answerChallenge(AnswerChallengeRequest answerChallengeRequest, String href) throws ProcessingException {

        IDXResponse idxResponse;

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                href,
                null,
                getHttpHeaders(false),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(answerChallengeRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            idxResponse = objectMapper.convertValue(responseJsonNode, IDXResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return idxResponse;
    }

    @Override
    public IDXResponse cancel(String stateHandle) throws ProcessingException {

        IDXResponse idxResponse;

        CancelRequest cancelRequest = CancelRequestBuilder.builder().withStateHandle(stateHandle).build();

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                clientConfiguration.getBaseUrl() + "/idp/idx/cancel",
                null,
                getHttpHeaders(false),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(cancelRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            idxResponse = objectMapper.convertValue(responseJsonNode, IDXResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return idxResponse;
    }

    @Override
    public IDXResponse enrollUpdateUserProfile(EnrollUserProfileUpdateRequest enrollUserProfileUpdateRequest,
                                               String href) throws ProcessingException {

        IDXResponse idxResponse;

        try {
            Request request = new DefaultRequest(
                    HttpMethod.POST,
                    href,
                    null,
                    getHttpHeaders(false),
                    new ByteArrayInputStream(objectMapper.writeValueAsBytes(enrollUserProfileUpdateRequest)),
                    -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            idxResponse = objectMapper.convertValue(responseJsonNode, IDXResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return idxResponse;
    }

    @Override
    public IDXResponse skip(SkipAuthenticatorEnrollmentRequest skipAuthenticatorEnrollmentRequest, String href) throws ProcessingException {

        IDXResponse idxResponse;

        try {
            Request request = new DefaultRequest(
                    HttpMethod.POST,
                    href,
                    null,
                    getHttpHeaders(false),
                    new ByteArrayInputStream(objectMapper.writeValueAsBytes(skipAuthenticatorEnrollmentRequest)),
                    -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            idxResponse = objectMapper.convertValue(responseJsonNode, IDXResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return idxResponse;
    }

    @Override
    public IDXResponse recover(RecoverRequest recoverRequest, String href) throws ProcessingException {

        IDXResponse idxResponse;

        try {
            Request request = new DefaultRequest(
                    HttpMethod.POST,
                    Strings.hasText(href) ? href : clientConfiguration.getBaseUrl() + "/idp/idx/recover",
                    null,
                    getHttpHeaders(false),
                    new ByteArrayInputStream(objectMapper.writeValueAsBytes(recoverRequest)),
                    -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            idxResponse = objectMapper.convertValue(responseJsonNode, IDXResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return idxResponse;
    }

    @Override
    public IDXResponse poll(PollRequest pollRequest, String href) throws ProcessingException {

        IDXResponse idxResponse;

        try {
            Request request = new DefaultRequest(
                    HttpMethod.POST,
                    Strings.hasText(href) ? href : clientConfiguration.getBaseUrl() + "/idp/idx/challenge/poll",
                    null,
                    getHttpHeaders(false),
                    new ByteArrayInputStream(objectMapper.writeValueAsBytes(pollRequest)),
                    -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            idxResponse = objectMapper.convertValue(responseJsonNode, IDXResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return idxResponse;
    }

    @Override
    public TokenResponse token(String grantType, String interactionCode, IDXClientContext idxClientContext) throws ProcessingException {
        String tokenUrl = normalizedIssuerUri(clientConfiguration.getIssuer(), "/v1/token");
        return token(tokenUrl, grantType, interactionCode, idxClientContext);
    }

    @Override
    public TokenResponse token(String url, String grantType, String interactionCode, IDXClientContext idxClientContext) throws ProcessingException {

        TokenResponse tokenResponse;

        StringBuilder urlParameters = new StringBuilder();
        urlParameters.append("grant_type=").append(grantType);
        urlParameters.append("&client_id=").append(clientConfiguration.getClientId());
        if (Strings.hasText(clientConfiguration.getClientSecret())) {
            urlParameters.append("&client_secret=").append(clientConfiguration.getClientSecret());
        }
        urlParameters.append("&interaction_code=").append(interactionCode);
        urlParameters.append("&code_verifier=").append(idxClientContext.getCodeVerifier());

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                url,
                null,
                getHttpHeaders(true),
                new ByteArrayInputStream(urlParameters.toString().getBytes(StandardCharsets.UTF_8)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                handleErrorResponse(request, response);
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            tokenResponse = objectMapper.convertValue(responseJsonNode, TokenResponse.class);

        } catch (IOException | HttpException e) {
            throw new ProcessingException(e);
        }

        return tokenResponse;
    }

    @Override
    public void revokeToken(String tokenType, String token) throws ProcessingException {

        StringBuilder urlParameters = new StringBuilder();
        urlParameters.append("client_id=").append(clientConfiguration.getClientId());
        if (Strings.hasText(clientConfiguration.getClientSecret())) {
            urlParameters.append("&client_secret=").append(clientConfiguration.getClientSecret());
        }
        urlParameters.append("&token_type_hint=").append(tokenType);
        urlParameters.append("&token=").append(token);

        try {
            Request request = new DefaultRequest(
                    HttpMethod.POST,
                    normalizedIssuerUri(clientConfiguration.getIssuer(), "/v1/revoke"),
                    null,
                    getHttpHeaders(true),
                    new ByteArrayInputStream(urlParameters.toString().getBytes(StandardCharsets.UTF_8)),
                    -1L);

            requestExecutor.executeRequest(request);
        } catch (HttpException e) {
            throw new ProcessingException(e);
        }
    }

    @Override
    public Response verifyEmailToken(String token) throws ProcessingException {

        StringBuilder urlParameter = new StringBuilder();
        urlParameter.append("token=").append(token);

        try {
            Request request = new DefaultRequest(
                    HttpMethod.GET,
                    clientConfiguration.getBaseUrl() + "/email/verify",
                    null,
                    getHttpHeaders(false),
                    new ByteArrayInputStream(urlParameter.toString().getBytes(StandardCharsets.UTF_8)),
                    -1L);

            return requestExecutor.executeRequest(request);
        } catch (HttpException e) {
            throw new ProcessingException(e);
        }
    }

    private void handleErrorResponse(Request request, Response response) throws IOException, ProcessingException {

        int httpStatus = response.getHttpStatus();
        String errorMsg = "Request to " + request.getResourceUrl() + " failed.";

        JsonNode errorResponseJson;

        if (response.getHeaders().getContentType() != null &&
                (response.getHeaders().getContentType().toString().contains("application/json") ||
                response.getHeaders().getContentType().toString().contains("application/ion+json"))) {
            errorResponseJson = objectMapper.readTree(response.getBody());
            ErrorResponse errorResponseDetails = objectMapper.convertValue(errorResponseJson, ErrorResponse.class);
            if (errorResponseDetails.getError() == null && errorResponseDetails.getMessages() == null) {
                getErrorsFromRemediationOptions(errorResponseDetails, errorResponseJson);
            }
            throw new ProcessingException(httpStatus, errorMsg, errorResponseDetails);
        } else {
            throw new ProcessingException(httpStatus, errorMsg);
        }
    }

    private void getErrorsFromRemediationOptions(ErrorResponse errorResponseDetails, JsonNode errorResponseJson) {

        IDXResponse idxResponse = objectMapper.convertValue(errorResponseJson, IDXResponse.class);
        if(idxResponse != null && idxResponse.remediation() != null) {
            for (RemediationOption remediationOption : idxResponse.remediation().remediationOptions()) {
                if(remediationOption != null) {
                    for (FormValue formValue : remediationOption.form()) {
                        if(formValue != null && formValue.form() != null) {
                            for (FormValue messageFormValue : formValue.form().getValue()) {
                                if (messageFormValue.messages != null) {
                                    errorResponseDetails.setMessages(messageFormValue.messages);
                                    return;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    private HttpHeaders getHttpHeaders(boolean isOAuth2Endpoint) {

        HttpHeaders httpHeaders = new HttpHeaders();

        if (isOAuth2Endpoint) {
            httpHeaders.add("Content-Type", "application/x-www-form-urlencoded");
            httpHeaders.add("Accept", "application/json");
        } else {
            httpHeaders.add("Content-Type", "application/ion+json; okta-version=1.0.0");
            httpHeaders.add("Accept", "application/ion+json; okta-version=1.0.0");
        }

        String userAgentValue = ApplicationInfo.get().entrySet().stream()
                .map(entry -> entry.getKey() + "/" + entry.getValue())
                .collect(Collectors.joining(" "));

        // value would look like (for e.g.): okta-idx-java/3.0.0-SNAPSHOT java/1.8.0_322 Mac OS X/12.3.1
        httpHeaders.add(HttpHeaders.USER_AGENT, userAgentValue);
        httpHeaders.add("Connection", "close");
        return httpHeaders;
    }
}
