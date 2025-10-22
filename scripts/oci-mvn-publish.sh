#!/bin/bash
#
# Copyright 2021-Present Okta, Inc.
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


# This script publishes a open source Maven project to Sonatype OSSRH (and on to Maven Central).
# It requires:
# - Sonatype credentials (username/password)
# - A GPG key for signing the artifacts
# - A settings.xml file, expected at 'src/ci/settings.xml'

set -e

function get_secret_from_terminus() {
	local SECRET_NAME="$1"
	local SECRET_ENV_VAR="$2"

	get_terminus_secret "/" "${SECRET_NAME}" "${SECRET_ENV_VAR}"

	if [ -z "${!SECRET_ENV_VAR}" ]; then
		echo "ERROR: Variable ${SECRET_ENV_VAR} in project is empty." >&2
		echo "Does your repository have access to the 'sonatype' project on Terminus?" >&2
		exit 1
	fi
}

function fetch_gpg() {
	echo "INFO: Setting up GPG..."
	get_secret_from_terminus gpg_tar_archive GPG_TAR_ARCHIVE

	[ -d "${HOME}/.gnupg" ] && mv "${HOME}/.gnupg" "${HOME}/.gnupg.original"
	mkdir -p ~/.gnupg

	echo "${GPG_TAR_ARCHIVE}" | base64 --decode -i - | tar x -C ~/.gnupg

	chmod 700 ~/.gnupg
	chmod 600 ~/.gnupg/*
	echo "INFO: GPG setup complete."
}

java17_0

echo "INFO: Starting Maven Central publishing process..."

echo "INFO: Fetching secrets from Terminus..."
get_secret_from_terminus sonatype_user SONATYPE_USERNAME
get_secret_from_terminus sonatype_password SONATYPE_PASSWORD
get_secret_from_terminus gpg_passphrase GPG_PASSPHRASE
get_secret_from_terminus gpg_keyid GPG_KEYID

fetch_gpg

PROJECT_ROOT="$(dirname "$0")/.."
SETTINGS_FILE="${PROJECT_ROOT}/src/ci/settings.xml"

# Change to the project root directory before executing Maven commands
echo "INFO: Changing directory to project root: ${PROJECT_ROOT}"
cd "${PROJECT_ROOT}" || {
    echo "ERROR: Failed to change directory to ${PROJECT_ROOT}" >&2
    exit 1
}

echo "INFO: Using Maven settings file: ${SETTINGS_FILE}"

if [ ! -f "${SETTINGS_FILE}" ]; then
    echo "ERROR: Maven settings file not found at '${SETTINGS_FILE}'" >&2
    exit 1
fi

AUTO_PUBLISH_FLAG=""
if [ "${AUTO_PUBLISH}" = "true" ]; then
    AUTO_PUBLISH_FLAG="-Dauto.publish=true"
fi

# --- 4. Execute Maven Deploy ---
# The 'deploy' phase will compile, test, package, sign, and upload the artifact.
# The 'central-publishing-maven-plugin' will automatically close and release the staging repository if autoPublish is set.
# We pass credentials and GPG info securely as command-line properties.
echo "INFO: Running 'mvn deploy'..."
./mvnw -B -s "${SETTINGS_FILE}" deploy \
  -Dgpg.keyname="${GPG_KEYID}" \
  -Dgpg.passphrase="${GPG_PASSPHRASE}" \
  ${AUTO_PUBLISH_FLAG}

echo "INFO: Maven artifact published successfully to Sonatype."