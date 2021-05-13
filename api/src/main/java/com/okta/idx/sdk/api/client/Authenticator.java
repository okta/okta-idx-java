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
        private final String label;

        Factor(String id, String method, String enrollmentId, String label) {
            this.id = id;
            this.method = method;
            this.enrollmentId = enrollmentId;
            this.label = label;
        }

        String getId() {
            return id;
        }

        public String getMethod() {
            return method;
        }

        String getEnrollmentId() {
            return enrollmentId;
        }

        public String getLabel() {
            return label;
        }
    }

    private final String id;
    private final String label;
    private final List<Factor> factors;
    private final boolean hasNestedFactors;

    Authenticator(String id, String label, List<Factor> factors, boolean hasNestedFactors) {
        this.id = id;
        this.label = label;
        this.factors = factors;
        this.hasNestedFactors = hasNestedFactors;
    }

    public String getId() {
        return id;
    }

    public String getLabel() {
        return label;
    }

    public List<Factor> getFactors() {
        return factors;
    }

    boolean hasNestedFactors() {
        return hasNestedFactors;
    }
}
