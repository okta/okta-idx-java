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
import com.okta.idx.sdk.api.exception.ProcessingException;
import env.a18n.client.response.A18NEmail;
import env.a18n.client.response.A18NProfile;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class BaseA18NClient implements A18NClient {

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
            System.out.println(e);
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
            System.out.println(e);
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
            System.out.println(e);
        }
        return email;
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
