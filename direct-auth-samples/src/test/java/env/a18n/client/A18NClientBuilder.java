package env.a18n.client;

import java.util.Set;

abstract class A18NClientBuilder {

    public abstract A18NClientBuilder setIssuer(String issuer);

    public abstract A18NClientBuilder setClientId(String clientId);

    public abstract A18NClientBuilder setClientSecret(String clientSecret);

    public abstract A18NClientBuilder setScopes(Set<String> scopes);

    public abstract A18NClientBuilder setRedirectUri(String redirectUri);

    public abstract A18NClient build();
}
