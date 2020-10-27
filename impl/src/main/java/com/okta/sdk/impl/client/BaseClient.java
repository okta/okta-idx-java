package com.okta.sdk.impl.client;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.okta.commons.http.DefaultRequest;
import com.okta.commons.http.HttpHeaders;
import com.okta.commons.http.HttpMethod;
import com.okta.commons.http.Request;
import com.okta.commons.http.RequestExecutor;
import com.okta.commons.http.RequestExecutorFactory;
import com.okta.commons.http.Response;
import com.okta.commons.http.authc.DisabledAuthenticator;
import com.okta.commons.http.config.HttpClientConfiguration;
import com.okta.commons.lang.Classes;
import com.okta.sdk.model.AnswerChallengeRequest;
import com.okta.sdk.model.Cancel;
import com.okta.sdk.model.CancelRequest;
import com.okta.sdk.model.ChallengeRequest;
import com.okta.sdk.client.Client;
import com.okta.sdk.model.IdentifyRequest;
import com.okta.sdk.model.IntrospectRequest;
import com.okta.sdk.model.OktaIdentityEngineResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Set;

public class BaseClient implements Client {

    private static final Logger log = LoggerFactory.getLogger(BaseClient.class);

    private String issuer;
    private String clientId;
    private Set<String> scopes;

    private ObjectMapper objectMapper;

    private RequestExecutor requestExecutor;

    public BaseClient(String issuer, String clientId, Set<String> scopes) {

        this.issuer = issuer;
        this.clientId = clientId;
        this.scopes = scopes;

        this.objectMapper = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT)
            .setSerializationInclusion(JsonInclude.Include.NON_NULL);

        HttpClientConfiguration httpClientConfiguration = new HttpClientConfiguration();
        httpClientConfiguration.setBaseUrl(issuer);
        httpClientConfiguration.setRequestAuthenticator(new DisabledAuthenticator());

        String msg = "Unable to find a '" + RequestExecutorFactory.class.getName() + "' " +
            "implementation on the classpath.  Please ensure you have added the " +
            "okta-sdk-httpclient.jar file to your runtime classpath."; // TODO fix jar name
        this.requestExecutor = Classes.loadFromService(RequestExecutorFactory.class, msg).create(httpClientConfiguration);
    }

    @Override
    public OktaIdentityEngineResponse introspect(String stateHandle) {

        OktaIdentityEngineResponse oktaIdentityEngineResponse = null;

        IntrospectRequest introspectRequest = new IntrospectRequest(stateHandle);

        try {
            Request request = new DefaultRequest(HttpMethod.POST,
                issuer + "/idp/idx/introspect",
                null,
                getHttpHeaders(),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(introspectRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            oktaIdentityEngineResponse = objectMapper.convertValue(responseJsonNode, OktaIdentityEngineResponse.class);

        } catch (IOException e) {
            log.error("Error occurred:", e);
            //TODO: throw custom exception?
        }

        return oktaIdentityEngineResponse;
    }

    @Override
    public OktaIdentityEngineResponse identify(IdentifyRequest identifyRequest) {

        OktaIdentityEngineResponse oktaIdentityEngineResponse = null;

        try {
            Request request = new DefaultRequest(HttpMethod.POST,
                issuer + "/idp/idx/identify",
                null,
                getHttpHeaders(),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(identifyRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            oktaIdentityEngineResponse = objectMapper.convertValue(responseJsonNode, OktaIdentityEngineResponse.class);

        } catch (IOException e) {
            log.error("Error occurred:", e);
            //TODO: revisit
        }

        return oktaIdentityEngineResponse;
    }

    @Override
    public OktaIdentityEngineResponse challenge(ChallengeRequest challengeRequest) {

        OktaIdentityEngineResponse oktaIdentityEngineResponse = null;

        try {
            Request request = new DefaultRequest(HttpMethod.POST,
                issuer + "/idp/idx/challenge",
                null,
                getHttpHeaders(),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(challengeRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            oktaIdentityEngineResponse = objectMapper.convertValue(responseJsonNode, OktaIdentityEngineResponse.class);

        } catch (IOException e) {
            log.error("Error occurred:", e);
            //TODO: revisit
        }

        return oktaIdentityEngineResponse;
    }

    @Override
    public OktaIdentityEngineResponse answerChallenge(AnswerChallengeRequest answerChallengeRequest) {

        OktaIdentityEngineResponse oktaIdentityEngineResponse = null;

        try {
            Request request = new DefaultRequest(HttpMethod.POST,
                issuer + "/idp/idx/challenge/answer",
                null,
                getHttpHeaders(),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(answerChallengeRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            oktaIdentityEngineResponse = objectMapper.convertValue(responseJsonNode, OktaIdentityEngineResponse.class);

        } catch (IOException e) {
            log.error("Error occurred:", e);
            //TODO: revisit
        }

        return oktaIdentityEngineResponse;
    }

    @Override
    public OktaIdentityEngineResponse cancel(Cancel cancel) {

        OktaIdentityEngineResponse oktaIdentityEngineResponse = null;

        CancelRequest cancelRequest = new CancelRequest(String.valueOf(cancel.getValue()[0].value));

        try {
            Request request = new DefaultRequest(HttpMethod.POST,
                issuer + "/idp/idx/cancel",
                null,
                getHttpHeaders(),
                new ByteArrayInputStream(objectMapper.writeValueAsBytes(cancelRequest)),
                -1L);

            Response response = requestExecutor.executeRequest(request);

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            oktaIdentityEngineResponse = objectMapper.convertValue(responseJsonNode, OktaIdentityEngineResponse.class);

        } catch (IOException e) {
            log.error("Error occurred:", e);
            //TODO: revisit
        }

        return oktaIdentityEngineResponse;
    }

    private HttpHeaders getHttpHeaders() {
        HttpHeaders httpHeaders = new HttpHeaders();
        httpHeaders.add("Content-Type", "application/ion+json; okta-version=1.0.0");
        httpHeaders.add("Content-Type", "application/ion+json; okta-version=1.0.0");
        return httpHeaders;
    }
}
