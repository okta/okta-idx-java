# Test disabled since Okta OIDC IdP login test covers this feature
@ignore
Feature: 5.2 Direct Auth Social Login with MFA

  Scenario: 5.2.1 Mary logs in with a social IDP and gets an error message
    Given Mary navigates to the Basic Login View
    When she clicks the "Login with Facebook" button
    And logs in to Facebook with USERNAME_FACEBOOK_MFA and PASSWORD_FACEBOOK_MFA
    And the remediation returns "MFA_REQUIRED"
    Then Mary should see an interaction_required error message
