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

import com.okta.commons.configcheck.ConfigurationValidator;
import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Collections;
import com.okta.commons.lang.Strings;
import com.okta.idx.sdk.api.client.IDXClient;
import com.okta.idx.sdk.api.client.IDXClientBuilder;
import com.okta.idx.sdk.impl.config.ClientConfiguration;
import com.okta.idx.sdk.impl.config.EnvironmentVariablesPropertiesSource;
import com.okta.idx.sdk.impl.config.OptionalPropertiesSource;
import com.okta.idx.sdk.impl.config.PropertiesSource;
import com.okta.idx.sdk.impl.config.ResourcePropertiesSource;
import com.okta.idx.sdk.impl.config.SystemPropertiesSource;
import com.okta.idx.sdk.impl.config.YAMLPropertiesSource;
import com.okta.idx.sdk.impl.io.ClasspathResource;
import com.okta.idx.sdk.impl.io.DefaultResourceFactory;
import com.okta.idx.sdk.impl.io.Resource;
import com.okta.idx.sdk.impl.io.ResourceFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/**
 * <p>The default {@link IDXClientBuilder} implementation. This looks for configuration files
 * in the following locations and order of precedence (last one wins).</p>
 * <ul>
 * <li>classpath:com/okta/sdk/config/okta.properties</li>
 * <li>classpath:com/okta/sdk/config/okta.yaml</li>
 * <li>classpath:okta.properties</li>
 * <li>classpath:okta.yaml</li>
 * <li>~/.okta/okta.yaml</li>
 * <li>Environment Variables (with dot notation converted to uppercase + underscores)</li>
 * <li>System Properties</li>
 * <li>Programmatically</li>
 * </ul>
 */
public class DefaultIDXClientBuilder implements IDXClientBuilder {

    private static final String ENVVARS_TOKEN   = "envvars";
    private static final String SYSPROPS_TOKEN  = "sysprops";
    private static final String OKTA_CONFIG_CP  = "com/okta/sdk/config/";
    private static final String OKTA_YAML       = "okta.yaml";
    private static final String OKTA_PROPERTIES = "okta.properties";

    private boolean allowNonHttpsForTesting = false;

    private ClientConfiguration clientConfig = new ClientConfiguration();

    public DefaultIDXClientBuilder() {
        this(new DefaultResourceFactory());
    }

    DefaultIDXClientBuilder(ResourceFactory resourceFactory) {
        Collection<PropertiesSource> sources = new ArrayList<>();

        for (String location : configSources()) {

            if (ENVVARS_TOKEN.equalsIgnoreCase(location)) {
                sources.add(EnvironmentVariablesPropertiesSource.oktaFilteredPropertiesSource());
            }
            else if (SYSPROPS_TOKEN.equalsIgnoreCase(location)) {
                sources.add(SystemPropertiesSource.oktaFilteredPropertiesSource());
            }
            else {
                Resource resource = resourceFactory.createResource(location);

                PropertiesSource wrappedSource;
                if (Strings.endsWithIgnoreCase(location, ".yaml")) {
                    wrappedSource = new YAMLPropertiesSource(resource);
                } else {
                    wrappedSource = new ResourcePropertiesSource(resource);
                }

                PropertiesSource propertiesSource = new OptionalPropertiesSource(wrappedSource);
                sources.add(propertiesSource);
            }
        }

        Map<String, String> props = new LinkedHashMap<>();

        for (PropertiesSource source : sources) {
            Map<String, String> srcProps = source.getProperties();
            props.putAll(srcProps);
        }

        if (Strings.hasText(props.get(DEFAULT_CLIENT_ISSUER_PROPERTY_NAME))) {
            clientConfig.setIssuer(props.get(DEFAULT_CLIENT_ISSUER_PROPERTY_NAME));
        }

        if (Strings.hasText(props.get(DEFAULT_CLIENT_ID_PROPERTY_NAME))) {
            clientConfig.setClientId(props.get(DEFAULT_CLIENT_ID_PROPERTY_NAME));
        }

        if (Strings.hasText(props.get(DEFAULT_CLIENT_SECRET_PROPERTY_NAME))) {
            clientConfig.setClientSecret(props.get(DEFAULT_CLIENT_SECRET_PROPERTY_NAME));
        }

        if (Strings.hasText(props.get(DEFAULT_CLIENT_SCOPES_PROPERTY_NAME))) {
            Set<String> scopes = new HashSet<>(Arrays.asList(props.get(DEFAULT_CLIENT_SCOPES_PROPERTY_NAME).split("[\\s,]+")));
            clientConfig.setScopes(scopes);
        }

        if (Strings.hasText(props.get(DEFAULT_CLIENT_REDIRECT_URI_PROPERTY_NAME))) {
            clientConfig.setRedirectUri(props.get(DEFAULT_CLIENT_REDIRECT_URI_PROPERTY_NAME));
        }

        if (Strings.hasText(props.get(DEFAULT_CLIENT_TESTING_DISABLE_HTTPS_CHECK_PROPERTY_NAME))) {
            allowNonHttpsForTesting = Boolean.parseBoolean(props.get(DEFAULT_CLIENT_TESTING_DISABLE_HTTPS_CHECK_PROPERTY_NAME));
        }
    }

    @Override
    public IDXClientBuilder setIssuer(String issuer) {
        this.clientConfig.setIssuer(issuer);
        return this;
    }

    @Override
    public IDXClientBuilder setClientId(String clientId) {
        this.clientConfig.setClientId(clientId);
        return this;
    }

    @Override
    public IDXClientBuilder setClientSecret(String clientSecret) {
        this.clientConfig.setClientSecret(clientSecret);
        return this;
    }

    @Override
    public IDXClientBuilder setScopes(Set<String> scopes) {
        this.clientConfig.setScopes(scopes);
        return this;
    }

    @Override
    public IDXClientBuilder setRedirectUri(String redirectUri) {
        this.clientConfig.setRedirectUri(redirectUri);
        return this;
    }

    @Override
    public IDXClient build() {
        this.validate();
        return new BaseIDXClient(this.clientConfig, null);
    }

    private void validate() throws IllegalArgumentException {
        ConfigurationValidator.assertOrgUrl(clientConfig.getIssuer(), this.allowNonHttpsForTesting);
        ConfigurationValidator.assertClientId(clientConfig.getClientId());
        Assert.isTrue(!Collections.isEmpty(clientConfig.getScopes()), "At least one scope is required");
        Assert.hasText(clientConfig.getRedirectUri(), "redirectUri is required");
    }

    private static String[] configSources() {

        // lazy load the config sources as the user.home system prop could change for testing
        return new String[] {
            ClasspathResource.SCHEME_PREFIX + OKTA_CONFIG_CP + OKTA_PROPERTIES,
            ClasspathResource.SCHEME_PREFIX + OKTA_CONFIG_CP + OKTA_YAML,
            ClasspathResource.SCHEME_PREFIX + OKTA_PROPERTIES,
            ClasspathResource.SCHEME_PREFIX + OKTA_YAML,
            System.getProperty("user.home") + File.separatorChar + ".okta" + File.separatorChar + OKTA_YAML,
            ENVVARS_TOKEN,
            SYSPROPS_TOKEN
        };
    }
}
