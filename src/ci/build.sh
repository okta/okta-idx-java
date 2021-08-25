#!/bin/bash
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

set -e

COMMON_SCRIPT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/common.sh"
CHROMEDRIVER_DOWNLOAD_SCRIPT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )/download_chromedriver.sh"
# shellcheck source=src/ci/common.sh
source "${COMMON_SCRIPT}"

cron () {
    echo "Running TRAVIS CRON task"
    echo "Downloading chromedriver"
    "${CHROMEDRIVER_DOWNLOAD_SCRIPT}"

    echo "Running Integration Tests against Trex Org"
    export OKTA_IDX_ISSUER=${TREX_OKTA_IDX_ISSUER}
    export OKTA_OAUTH2_ISSUER=${TREX_OKTA_IDX_ISSUER}
    export OKTA_CLIENT_TOKEN=${TREX_OKTA_CLIENT_TOKEN}
    export OKTA_CLIENT_ORGURL=${TREX_OKTA_CLIENT_ORGURL}
    export OKTA_IDX_CLIENTID=${TREX_OKTA_IDX_CLIENTID}
    export OKTA_IDX_CLIENTSECRET=${TREX_OKTA_IDX_CLIENTSECRET}
    export OKTA_OAUTH2_CLIENTID=${TREX_OKTA_IDX_CLIENTID}
    export OKTA_OAUTH2_CLIENTSECRET=${TREX_OKTA_IDX_CLIENTSECRET}

    ${MVN_CMD} clean verify
}

deploy () {
    echo "Downloading chromedriver"
    "${CHROMEDRIVER_DOWNLOAD_SCRIPT}"

    echo "Deploying SNAPSHOT build"
    ${MVN_CMD} deploy -Pci

    # also deploy the javadocs to the site
    git clone -b gh-pages "https://github.com/${REPO_SLUG}.git" target/gh-pages/
    ${MVN_CMD} javadoc:aggregate com.okta:okta-doclist-maven-plugin:generate jxr:aggregate -Ppub-docs -Pci
}

full_build () {
    echo "Downloading chromedriver"
    "${CHROMEDRIVER_DOWNLOAD_SCRIPT}"
    echo "Running mvn install"
    ${MVN_CMD} install -Pci
}

no_its_build () {
    echo "Skipping ITs, likely this build is a pull request from a fork"
    ${MVN_CMD} install -DskipITs -Pci
}

# if this build was triggered via a cron job, just scan the dependencies
if [ "${TRAVIS_EVENT_TYPE}" = "cron" ] ; then
    cron
else
    # run 'mvn deploy' if we can
    if [ "${DEPLOY}" = true ] ; then
        deploy
    else
        # else try to run the ITs if possible (for someone who has push access to the repo
        if [ "${RUN_ITS}" = true ] ; then
            full_build
        else
            # fall back to running an install and skip the ITs
            no_its_build
        fi
    fi
fi
