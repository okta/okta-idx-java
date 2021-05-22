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

function getOs() {
    # MacOS or Linux?
    sw_vers 2>/dev/null
    RET_VAL=$?
    if [[ ${RET_VAL} == 0 ]];
    then
      OS=mac
    else
      OS=*nix
    fi
    echo "OS: ${OS}"
}

function getChromeDriverVersion() {
    getOs
    # chrome version
    if [[ ${OS} == "mac" ]];
    then
      TEMP_CHROME_VER=$(/Applications/Google\ Chrome.app/Contents/MacOS/Google\ Chrome --version)
    else
      TEMP_CHROME_VER=$(google-chrome --product-version)
    fi
    echo "Chrome Version: ${TEMP_CHROME_VER}"
    CHROME_VER=$(echo "${TEMP_CHROME_VER}" | sed -En 's/[^0-9]*([0-9]+)\..*/\1/p')
    echo "Chrome Version: ${CHROME_VER}"

    CHROMEDRIVER_URL="https://chromedriver.storage.googleapis.com/LATEST_RELEASE_${CHROME_VER}"
    echo "${CHROMEDRIVER_URL}"

    CHROMEDRIVER_VERSION=$(curl "${CHROMEDRIVER_URL}")
    echo "${CHROMEDRIVER_VERSION}"
}

function downloadChromeDriver() {
  getChromeDriverVersion

  if [[ ${OS} == "mac" ]];
    then
      CHROMEDRIVER_DOWNLOAD_URL="https://chromedriver.storage.googleapis.com/${CHROMEDRIVER_VERSION}/chromedriver_mac64.zip"
    else
      CHROMEDRIVER_DOWNLOAD_URL="https://chromedriver.storage.googleapis.com/${CHROMEDRIVER_VERSION}/chromedriver_linux64.zip"
  fi
  echo "${CHROMEDRIVER_DOWNLOAD_URL}"

  curl "${CHROMEDRIVER_DOWNLOAD_URL}" --output chromedriver.zip
  unzip -o chromedriver.zip -d ./direct-auth-samples/
}

downloadChromeDriver