#!/bin/bash -x

setup_service java 1.8.222
setup_service google-chrome-stable ${DEFAULT_CHROME_VERSION}

export TRAVIS=true

export OKTA_IDX_ISSUER=https://java-idx-sdk.trexcloud.com/oauth2/default
export OIDC_IDP_ORG_URL=https://devex-oidc-idp.okta.com
export OKTA_IDX_REDIRECTURI=http://localhost:8080/authorization-code/callback
export OKTA_IDX_CLIENTID=0oa3r6wr7isN9LfmT0g7
get_vault_secret_key devex/java-idx-sdk-vars trex_client_secret OKTA_IDX_CLIENTSECRET
export OKTA_CLIENT_ORGURL=https://java-idx-sdk.trexcloud.com
get_vault_secret_key devex/java-idx-sdk-vars trex_client_token OKTA_CLIENT_TOKEN
get_vault_secret_key devex/java-idx-sdk-vars a18n_api_key A18N_API_KEY
export OKTA_IDX_SCOPES="openid email profile offline_access"
export USERNAME=mary@acme.com
export USERNAME_MFA=mary.mfa@acme.com
get_vault_secret_key devex/java-idx-sdk-vars password PASSWORD

# Run the tests
cd ${OKTA_HOME}/${REPO}
mvn clean install -DskipITs -Pci
./src/ci/download_chromedriver.sh
cd samples/embedded-auth-with-sdk
mvn clean install -P cucumber-it

RETURN_CODE=$?
if [[ "${RETURN_CODE}" -ne "0" ]]; then
    echo "E2E tests for embedded-auth-with-sdk failed!" 
    exit 1
fi
