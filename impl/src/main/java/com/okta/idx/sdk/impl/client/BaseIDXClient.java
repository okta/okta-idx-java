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
package com.okta.idx.sdk.impl.client;

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
import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Classes;
import com.okta.commons.lang.Strings;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.exception.ProcessingException;
import com.okta.idx.sdk.api.request.AnswerChallengeRequest;
import com.okta.idx.sdk.api.request.CancelRequest;
import com.okta.idx.sdk.api.request.CancelRequestBuilder;
import com.okta.idx.sdk.api.request.ChallengeRequest;
import com.okta.idx.sdk.api.request.EnrollRequest;
import com.okta.idx.sdk.api.request.EnrollUserProfileUpdateRequest;
import com.okta.idx.sdk.api.request.IdentifyRequest;
import com.okta.idx.sdk.api.request.IntrospectRequest;
import com.okta.idx.sdk.api.request.SkipAuthenticatorEnrollmentRequest;
import com.okta.idx.sdk.api.request.RecoverRequest;
import com.okta.idx.sdk.api.response.ErrorResponse;
import com.okta.idx.sdk.api.response.IDXResponse;
import com.okta.idx.sdk.api.response.InteractResponse;
import com.okta.idx.sdk.api.response.TokenResponse;
import com.okta.idx.sdk.impl.config.ClientConfiguration;
import com.okta.idx.sdk.impl.util.PkceUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;

public class BaseIDXClient implements IDXClient {

    private static final Logger log = LoggerFactory.getLogger(BaseIDXClient.class);

    private static final String USER_AGENT_HEADER_VALUE = "okta-idx-java/1.0.0";

    private final ClientConfiguration clientConfiguration;

    private final ObjectMapper objectMapper;
    private final RequestExecutor requestExecutor;

    private String codeVerifier;

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
    public InteractResponse interact() throws ProcessingException {

        InteractResponse interactResponse;

        try {
            codeVerifier = PkceUtil.generateCodeVerifier();
            String codeChallenge = PkceUtil.generateCodeChallenge(codeVerifier);
            String state = UUID.randomUUID().toString();

            StringBuilder urlParameters = new StringBuilder();
            urlParameters.append("client_id=").append(clientConfiguration.getClientId());
            urlParameters.append("&scope=").append(clientConfiguration.getScopes().stream()
                    .map(Object::toString).collect(Collectors.joining(" ")));
            urlParameters.append("&code_challenge=").append(codeChallenge);
            urlParameters.append("&code_challenge_method=").append(PkceUtil.CODE_CHALLENGE_METHOD);
            urlParameters.append("&redirect_uri=").append(clientConfiguration.getRedirectUri());
            urlParameters.append("&state=").append(state);

            Request request = new DefaultRequest(
                HttpMethod.POST,
                clientConfiguration.getIssuer() + "/v1/interact",
                null,
                getHttpHeaders(true),
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

        return interactResponse;
    }

    @Override
    public IDXResponse introspect(Optional<String> interactionHandleOptional) throws ProcessingException {

        IDXResponse idxResponse;

        String interactionHandle;

        if (!interactionHandleOptional.isPresent()) {
            interactionHandle = this.interact().getInteractionHandle();
        } else {
            interactionHandle = interactionHandleOptional.get();
        }

        IntrospectRequest introspectRequest = new IntrospectRequest(interactionHandle);

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
                    href,
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
    public TokenResponse token(String url, String grantType, String interactionCode) throws ProcessingException {

        TokenResponse tokenResponse;

        StringBuilder urlParameters = new StringBuilder();
        urlParameters.append("grant_type=").append(grantType);
        urlParameters.append("&client_id=").append(clientConfiguration.getClientId());
        if (Strings.hasText(clientConfiguration.getClientSecret())) {
            urlParameters.append("&client_secret=").append(clientConfiguration.getClientSecret());
        }
        urlParameters.append("&interaction_code=").append(interactionCode);
        urlParameters.append("&code_verifier=").append(codeVerifier);

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

    private void handleErrorResponse(Request request, Response response) throws IOException, ProcessingException {

        int httpStatus = response.getHttpStatus();
        String errorMsg = "Request to " + request.getResourceUrl() + " failed.";

        JsonNode errorResponseJson;

        if (response.getHeaders().getContentType() != null &&
                response.getHeaders().getContentType().toString().contains("application/json") ||
                response.getHeaders().getContentType().toString().contains("application/ion+json")) {
            errorResponseJson = objectMapper.readTree(response.getBody());
            ErrorResponse errorResponseDetails = objectMapper.convertValue(errorResponseJson, ErrorResponse.class);
            throw new ProcessingException(httpStatus, errorMsg, errorResponseDetails);
        } else {
            throw new ProcessingException(httpStatus, errorMsg);
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

        httpHeaders.add(HttpHeaders.USER_AGENT, USER_AGENT_HEADER_VALUE);
        return httpHeaders;
    }
}
