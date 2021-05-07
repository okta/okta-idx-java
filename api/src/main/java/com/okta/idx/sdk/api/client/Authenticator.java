/*
 * Copyright 2021-Present Okta, Inc.
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
package com.okta.idx.sdk.api.client;

import java.util.List;

public final class Authenticator {
    public static final class Factor {
        private final String id;
        private final String method;
        private final String enrollmentId;

        Factor(String id, String method, String enrollmentId) {
            this.id = id;
            this.method = method;
            this.enrollmentId = enrollmentId;
        }

        public String getMethod() {
            return method;
        }

        String getId() {
            return id;
        }

        String getEnrollmentId() {
            return enrollmentId;
        }
    }

    private final String method;
    private final List<Factor> factors;

    Authenticator(String method, List<Factor> factors) {
        this.method = method;
        this.factors = factors;
    }

    public String getMethod() {
        return method;
    }

    public List<Factor> getFactors() {
        return factors;
    }
}
