#!/bin/bash -x
#
# Copyright 2017-Present Okta, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

setup_service java 1.8.222
setup_service google-chrome-stable 89.0.4389.72-1
setup_service maven 3.5.4

export CI=true

export OKTA_IDX_ISSUER=https://java-idx-sdk-idfirst.okta.com/oauth2/default
export OKTA_IDX_REDIRECTURI=http://localhost:8080/authorization-code/callback
export OKTA_IDX_CLIENTID=0oarqdgy46BqaBlFo696
get_vault_secret_key devex/java-idx-sdk-vars trex_client_secret_password_optional OKTA_IDX_CLIENTSECRET
export OKTA_CLIENT_ORGURL=https://java-idx-sdk-idfirst.okta.com
get_vault_secret_key devex/java-idx-sdk-vars trex_client_token_password_optional OKTA_CLIENT_TOKEN
get_vault_secret_key devex/java-idx-sdk-vars a18n_api_key A18N_API_KEY
export OKTA_IDX_SCOPES="openid email profile offline_access"
export USERNAME=mary@acme.com
get_vault_secret_key devex/java-idx-sdk-vars password PASSWORD

# Run the tests
cd ${OKTA_HOME}/${REPO}
mvn clean install -DskipITs -Pci
./src/ci/download_chromedriver.sh

# Rename the features directory to point to password_optional_features
cd samples/embedded-auth-with-sdk
mv src/test/resources/features src/test/resources/_features
mv src/test/resources/password_optional_features src/test/resources/features

mvn clean install -P cucumber-it

RETURN_CODE=$?
if [[ "${RETURN_CODE}" -ne "0" ]]; then
    echo "E2E tests for embedded-auth-with-sdk failed!" 
    exit 1
fi
