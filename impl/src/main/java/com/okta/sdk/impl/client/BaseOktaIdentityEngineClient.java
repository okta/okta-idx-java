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
package com.okta.sdk.impl.client;

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
import com.okta.sdk.api.client.OktaIdentityEngineClient;
import com.okta.sdk.api.exception.ProcessingException;
import com.okta.sdk.api.request.AnswerChallengeRequest;
import com.okta.sdk.api.request.CancelRequest;
import com.okta.sdk.api.request.CancelRequestBuilder;
import com.okta.sdk.api.request.ChallengeRequest;
import com.okta.sdk.api.request.IdentifyRequest;
import com.okta.sdk.api.request.IntrospectRequest;
import com.okta.sdk.api.response.InteractResponse;
import com.okta.sdk.api.response.OktaIdentityEngineResponse;
import com.okta.sdk.api.response.TokenResponse;
import com.okta.sdk.impl.config.ClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;
import java.util.stream.Collectors;

public class BaseOktaIdentityEngineClient implements OktaIdentityEngineClient {

    private static final Logger log = LoggerFactory.getLogger(BaseOktaIdentityEngineClient.class);

    private static final String USER_AGENT_HEADER_VALUE = "okta-idx-java/1.0.0";

    private final ClientConfiguration clientConfiguration;

    private final ObjectMapper objectMapper;
    private final RequestExecutor requestExecutor;

    public BaseOktaIdentityEngineClient(ClientConfiguration clientConfiguration, RequestExecutor requestExecutor) {

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
            String msg = "Unable to find a '" + RequestExecutorFactory.class.getName() + "' " +
                "implementation on the classpath.  Please ensure you have added the " +
                "okta-sdk-httpclient.jar file to your runtime classpath."; // TODO fix jar name
            this.requestExecutor = Classes.loadFromService(RequestExecutorFactory.class, msg).create(httpClientConfiguration);
        }
    }

    @Override
    public InteractResponse interact() throws ProcessingException {

        InteractResponse interactResponse;

        String urlParameters = "scope=" + clientConfiguration.getScopes().stream()
            .map(Object::toString).collect(Collectors.joining(" "));

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                clientConfiguration.getIssuer() + "/oauth2/v1/interact",
                null,
                getJsonHttpHeaders(),
                new ByteArrayInputStream(urlParameters.getBytes(StandardCharsets.UTF_8)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            interactResponse = objectMapper.convertValue(responseJsonNode, InteractResponse.class);

            Assert.notNull(interactResponse, "interact response cannot be null");
            Assert.notNull(interactResponse.getInteractionHandle(), "interactionHandle cannot be null");

        } catch (IOException | IllegalArgumentException | HttpException e) {
            throw new ProcessingException(e);
        }

        return interactResponse;
    }

    @Override
    public OktaIdentityEngineResponse introspect(String interactionHandle) throws ProcessingException {

        OktaIdentityEngineResponse oktaIdentityEngineResponse;

        IntrospectRequest introspectRequest = new IntrospectRequest(interactionHandle);

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                clientConfiguration.getIssuer() + "/idp/idx/introspect",
                null,
                getIonJsonHttpHeaders(),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(introspectRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            oktaIdentityEngineResponse = objectMapper.convertValue(responseJsonNode, OktaIdentityEngineResponse.class);

        } catch (IOException | IllegalArgumentException | HttpException e) {
            throw new ProcessingException(e);
        }

        return oktaIdentityEngineResponse;
    }

    @Override
    public OktaIdentityEngineResponse identify(IdentifyRequest identifyRequest) throws ProcessingException {

        OktaIdentityEngineResponse oktaIdentityEngineResponse;

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                clientConfiguration.getIssuer() + "/idp/idx/identify",
                null,
                getIonJsonHttpHeaders(),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(identifyRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            oktaIdentityEngineResponse = objectMapper.convertValue(responseJsonNode, OktaIdentityEngineResponse.class);

        } catch (IOException | IllegalArgumentException | HttpException e) {
            throw new ProcessingException(e);
        }

        return oktaIdentityEngineResponse;
    }

    @Override
    public OktaIdentityEngineResponse challenge(ChallengeRequest challengeRequest) throws ProcessingException {

        OktaIdentityEngineResponse oktaIdentityEngineResponse;

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                clientConfiguration.getIssuer() + "/idp/idx/challenge",
                null,
                getIonJsonHttpHeaders(),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(challengeRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            oktaIdentityEngineResponse = objectMapper.convertValue(responseJsonNode, OktaIdentityEngineResponse.class);

        } catch (IOException | IllegalArgumentException | HttpException e) {
            throw new ProcessingException(e);
        }

        return oktaIdentityEngineResponse;
    }

    @Override
    public OktaIdentityEngineResponse answerChallenge(AnswerChallengeRequest answerChallengeRequest) throws ProcessingException {

        OktaIdentityEngineResponse oktaIdentityEngineResponse;

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                clientConfiguration.getIssuer() + "/idp/idx/challenge/answer",
                null,
                getIonJsonHttpHeaders(),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(answerChallengeRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            oktaIdentityEngineResponse = objectMapper.convertValue(responseJsonNode, OktaIdentityEngineResponse.class);

        } catch (IOException | IllegalArgumentException | HttpException e) {
            throw new ProcessingException(e);
        }

        return oktaIdentityEngineResponse;
    }

    @Override
    public OktaIdentityEngineResponse cancel(String stateHandle) throws ProcessingException {

        OktaIdentityEngineResponse oktaIdentityEngineResponse;

        CancelRequest cancelRequest = CancelRequestBuilder.builder().withStateHandle(stateHandle).build();

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                clientConfiguration.getIssuer() + "/idp/idx/cancel",
                null,
                getIonJsonHttpHeaders(),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(cancelRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            oktaIdentityEngineResponse = objectMapper.convertValue(responseJsonNode, OktaIdentityEngineResponse.class);

        } catch (IOException | IllegalArgumentException | HttpException e) {
            throw new ProcessingException(e);
        }

        return oktaIdentityEngineResponse;
    }

    @Override
    public OktaIdentityEngineResponse start(Optional<String> interactionHandleOptional) throws ProcessingException {

        OktaIdentityEngineResponse oktaIdentityEngineResponse;

        String interactionHandle;

        if (!interactionHandleOptional.isPresent()) {
            interactionHandle = this.interact().getInteractionHandle();
        } else {
            interactionHandle = interactionHandleOptional.get();
        }

        // introspect
        oktaIdentityEngineResponse = this.introspect(interactionHandle);

        return oktaIdentityEngineResponse;
    }

    @Override
    public TokenResponse token(String grantType, String interactionCode) throws ProcessingException {

        TokenResponse tokenResponse;

        String urlParameters = "grant_type=" + grantType + "&interaction_code=" + interactionCode;

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                clientConfiguration.getIssuer() + "/oauth2/v1/token",
                null,
                getJsonHttpHeaders(),
                new ByteArrayInputStream(urlParameters.getBytes(StandardCharsets.UTF_8)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            tokenResponse = objectMapper.convertValue(responseJsonNode, TokenResponse.class);

        } catch (IOException | IllegalArgumentException | HttpException e) {
            throw new ProcessingException(e);
        }

        return tokenResponse;
    }

    private HttpHeaders getJsonHttpHeaders() {
        HttpHeaders httpHeaders = new HttpHeaders();

        String authHeaderStr;

        if (Strings.hasText(clientConfiguration.getClientSecret())) {
            // confidential clients have clientSecret; Auth header is needed
            authHeaderStr = clientConfiguration.getClientId() + ":" + clientConfiguration.getClientSecret();
            httpHeaders.add("Authorization", "Basic " + Base64.getEncoder().encodeToString(authHeaderStr.getBytes(StandardCharsets.UTF_8)));
        }
//        else {
//            // public client
//            // TODO: Auth header is needed?
//        }

        httpHeaders.add("Content-Type", "application/x-www-form-urlencoded");
        httpHeaders.add("Accept", "application/json");
        httpHeaders.add(HttpHeaders.USER_AGENT, USER_AGENT_HEADER_VALUE);
        return httpHeaders;
    }

    private HttpHeaders getIonJsonHttpHeaders() {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Content-Type", "application/ion+json; okta-version=1.0.0");
        httpHeaders.add("Accept", "application/ion+json; okta-version=1.0.0");
        httpHeaders.add(HttpHeaders.USER_AGENT, USER_AGENT_HEADER_VALUE);
        return httpHeaders;
    }
}