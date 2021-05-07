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
