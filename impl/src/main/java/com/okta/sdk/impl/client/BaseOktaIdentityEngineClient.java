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
import com.okta.commons.http.MediaType;
import com.okta.commons.http.Request;
import com.okta.commons.http.RequestExecutor;
import com.okta.commons.http.RequestExecutorFactory;
import com.okta.commons.http.Response;
import com.okta.commons.http.authc.DisabledAuthenticator;
import com.okta.commons.http.config.HttpClientConfiguration;
import com.okta.commons.lang.Classes;
import com.okta.commons.lang.Strings;
import com.okta.sdk.api.client.OktaIdentityEngineClient;
import com.okta.sdk.api.exception.ProcessingException;
import com.okta.sdk.api.request.AnswerChallengeRequest;
import com.okta.sdk.api.request.BaseRequest;
import com.okta.sdk.api.request.CancelRequest;
import com.okta.sdk.api.request.ChallengeRequest;
import com.okta.sdk.api.request.IdentifyRequest;
import com.okta.sdk.api.request.InteractRequest;
import com.okta.sdk.api.request.IntrospectRequest;
import com.okta.sdk.api.response.OktaIdentityEngineResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Set;

public class BaseOktaIdentityEngineClient implements OktaIdentityEngineClient {

    private static final Logger log = LoggerFactory.getLogger(BaseOktaIdentityEngineClient.class);

    private final String issuer;
    private final String clientId;
    private final Set<String> scopes;

    private final ObjectMapper objectMapper;
    private final RequestExecutor requestExecutor;

    public BaseOktaIdentityEngineClient(String issuer, String clientId, Set<String> scopes, RequestExecutor requestExecutor) {

        this.issuer = issuer;
        this.clientId = clientId;
        this.scopes = scopes;

        this.objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

        HttpClientConfiguration httpClientConfiguration = new HttpClientConfiguration();
        httpClientConfiguration.setBaseUrl(issuer);
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
    public OktaIdentityEngineResponse interact() throws ProcessingException {

        OktaIdentityEngineResponse oktaIdentityEngineResponse;

        InteractRequest interactRequest = new InteractRequest(this.clientId, this.scopes);

        HttpHeaders httpHeaders = new HttpHeaders();
        //httpHeaders.add("Authorization", ""); //TODO: is this header needed?
        httpHeaders.add("Content-Type", MediaType.APPLICATION_FORM_URLENCODED_VALUE);

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                issuer + "/oauth2/v1/interact",
                null,
                httpHeaders,
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(interactRequest)),
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
    public OktaIdentityEngineResponse introspect(String stateHandle) throws ProcessingException {

        OktaIdentityEngineResponse oktaIdentityEngineResponse;

        IntrospectRequest introspectRequest = new IntrospectRequest(stateHandle);

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                issuer + "/idp/idx/introspect",
                null,
                getHttpHeaders(),
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
                issuer + "/idp/idx/identify",
                null,
                getHttpHeaders(),
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

        OktaIdentityEngineResponse oktaIdentityEngineResponse = null;

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                issuer + "/idp/idx/challenge",
                null,
                getHttpHeaders(),
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
                issuer + "/idp/idx/challenge/answer",
                null,
                getHttpHeaders(),
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

        BaseRequest cancelRequest = new CancelRequest(stateHandle);

        try {
            Request request = new DefaultRequest(
                HttpMethod.POST,
                issuer + "/idp/idx/cancel",
                null,
                getHttpHeaders(),
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
    public OktaIdentityEngineResponse start(String stateHandle) throws ProcessingException {

        OktaIdentityEngineResponse oktaIdentityEngineResponse = null;

        if (Strings.hasText(stateHandle)) {
            //get a new state handle
            stateHandle = "";
        }

        //interact
        //oktaIdentityEngineResponse = this.interact();

        //TODO - grab stataHandle from interact response
        //stateHandle =

        //introspect
        //oktaIdentityEngineResponse = this.introspect(stateHandle);

        return oktaIdentityEngineResponse;
    }

    private HttpHeaders getHttpHeaders() {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Content-Type", "application/ion+json; okta-version=1.0.0");
        httpHeaders.add("Accept", "application/ion+json; okta-version=1.0.0");
        return httpHeaders;
    }
}
