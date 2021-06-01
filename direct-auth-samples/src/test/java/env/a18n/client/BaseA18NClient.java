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
package env.a18n.client;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.okta.commons.http.*;
import com.okta.commons.http.authc.DisabledAuthenticator;
import com.okta.commons.http.config.HttpClientConfiguration;
import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Classes;
import com.okta.idx.sdk.api.config.ClientConfiguration;
import env.a18n.client.response.A18NEmail;
import env.a18n.client.response.A18NProfile;
import org.apache.commons.io.IOUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;

public class BaseA18NClient implements A18NClient {

    private final Logger logger = LoggerFactory.getLogger(BaseA18NClient.class);

    private final ClientConfiguration clientConfiguration;
    private final ObjectMapper objectMapper;
    private final RequestExecutor requestExecutor;

    public BaseA18NClient(ClientConfiguration clientConfiguration, RequestExecutor requestExecutor) {

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
    public A18NProfile createProfile() {

        A18NProfile profile = null;

        try {
            Request request = new DefaultRequest(
                    HttpMethod.POST,
                    "https://api.a18n.help/v1/profile",
                    null,
                    getHttpHeaders(),
                    new ByteArrayInputStream("profile".getBytes(StandardCharsets.UTF_8)),
                    -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                throw new Exception(response.toString());
            }

            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());

            profile = objectMapper.convertValue(responseJsonNode, A18NProfile.class);

        } catch (Exception e) {
            logger.debug("Fail to create A18N profile", e);
        }

        return profile;
    }

    @Override
    public void deleteProfile(A18NProfile profile) {

        try {
            Request request = new DefaultRequest(
                    HttpMethod.DELETE,
                    profile.getUrl(),
                    null,
                    getHttpHeaders(),
                    null,
                    -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 204) {
                throw new Exception(response.toString());
            }
        } catch (Exception e) {
            logger.debug("Fail to delete A18N profile", e);
        }
    }

    @Override
    public A18NEmail getLatestEmail(A18NProfile profile) {

        A18NEmail email = null;

        try {
            Request request = new DefaultRequest(
                    HttpMethod.GET,
                    profile.getUrl() + "/email/latest",
                    null,
                    getHttpHeaders(),
                    null,
                    -1L);

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                throw new Exception(response.toString());
            }
            JsonNode responseJsonNode = objectMapper.readTree(response.getBody());
            email = objectMapper.convertValue(responseJsonNode, A18NEmail.class);
        } catch (Exception e) {
            logger.debug("Fail to get last email for "+ profile.getEmailAddress(), e);
        }
        return email;
    }

    @Override
    public String getLatestSmsContent(A18NProfile profile) {
        String sms = null;

        try {
            Request request = new DefaultRequest(
                    HttpMethod.GET,
                    profile.getUrl() + "/sms/latest/content",
                    null,
                    getHttpHeaders());

            Response response = requestExecutor.executeRequest(request);

            if (response.getHttpStatus() != 200) {
                throw new Exception(response.toString());
            }
            sms = IOUtils.toString(response.getBody(), StandardCharsets.UTF_8);
        } catch (Exception e) {
            logger.debug("Fail to get last sms for " + profile.getEmailAddress(), e);
        }
        return sms;
    }

    private HttpHeaders getHttpHeaders() {
        HttpHeaders httpHeaders = new HttpHeaders();
        String apiKey = System.getenv("A18N_API_KEY");
        Assert.notNull(apiKey);
        httpHeaders.add("x-api-key", apiKey);
        httpHeaders.add("Content-Type", "application/json");
        return httpHeaders;
    }
}
