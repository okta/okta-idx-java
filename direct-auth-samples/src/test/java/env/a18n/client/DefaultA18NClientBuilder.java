package env.a18n.client;

import com.okta.commons.configcheck.ConfigurationValidator;
import com.okta.commons.lang.Assert;
import com.okta.commons.lang.Collections;
import com.okta.commons.lang.Strings;
import com.okta.idx.sdk.api.config.*;
import com.okta.idx.sdk.api.io.ClasspathResource;
import com.okta.idx.sdk.api.io.DefaultResourceFactory;
import com.okta.idx.sdk.api.io.Resource;
import com.okta.idx.sdk.api.io.ResourceFactory;

import java.io.File;
import java.util.*;

import static com.okta.idx.sdk.api.util.Constants.*;
import static com.okta.idx.sdk.api.util.Constants.DEFAULT_CLIENT_TESTING_DISABLE_HTTPS_CHECK_PROPERTY_NAME;

public class DefaultA18NClientBuilder extends A18NClientBuilder {

    private static final String ENVVARS_TOKEN   = "envvars";
    private static final String SYSPROPS_TOKEN  = "sysprops";
    private static final String OKTA_CONFIG_CP  = "com/okta/sdk/config/";
    private static final String OKTA_YAML       = "okta.yaml";
    private static final String OKTA_PROPERTIES = "okta.properties";

    private boolean allowNonHttpsForTesting = false;

    private final ClientConfiguration clientConfig = new ClientConfiguration();

    public DefaultA18NClientBuilder() {
        this(new DefaultResourceFactory());
    }

    DefaultA18NClientBuilder(ResourceFactory resourceFactory) {
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

        clientConfig.setIssuer("https://api.a18n.help");

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
    public A18NClientBuilder setIssuer(String issuer) {
        this.clientConfig.setIssuer(issuer);
        return this;
    }

    @Override
    public A18NClientBuilder setClientId(String clientId) {
        return null;
    }

    @Override
    public A18NClientBuilder setClientSecret(String clientSecret) {
        return null;
    }

    @Override
    public A18NClientBuilder setScopes(Set<String> scopes) {
        return null;
    }

    @Override
    public A18NClientBuilder setRedirectUri(String redirectUri) {
        return null;
    }

    @Override
    public A18NClient build() {
        this.validate();
        return new BaseA18NClient(this.clientConfig, null);
    }

    private void validate() throws IllegalArgumentException {
        //TODO Validate params here
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
