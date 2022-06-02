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

export OKTA_OAUTH2_ISSUER=https://java-idx-sdk.trexcloud.com/oauth2/default
export OKTA_OAUTH2_REDIRECTURI=http://localhost:8080/authorization-code/callback
export OKTA_OAUTH2_CLIENTID=0oa3r6wr7isN9LfmT0g7
get_vault_secret_key devex/java-idx-sdk-vars trex_client_secret OKTA_OAUTH2_CLIENTSECRET
export OKTA_IDX_SCOPES="openid email profile offline_access"
export USERNAME=mary@acme.com
get_vault_secret_key devex/java-idx-sdk-vars password PASSWORD

# Run the tests
cd ${OKTA_HOME}/${REPO}
mvn clean install -Pci
./src/ci/download_chromedriver.sh
cd samples/embedded-sign-in-widget
mvn clean install -P cucumber-it

RETURN_CODE=$?
if [[ "${RETURN_CODE}" -ne "0" ]]; then
    echo "E2E tests for embedded-sign-in-widget failed!"
    exit 1
fi
