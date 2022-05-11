Feature: 5.2 Direct Auth Social Login with MFA

  # interaction_required error is not being returned
  @ignore
  Scenario: 5.2.1 Mary logs in with a social IDP and gets an error message
    Given Mary navigates to the Basic Login View
    When she clicks the "Login with OIDC" button
    And logs in to OIDC IdP with USERNAME_MFA and PASSWORD
    And the remediation returns "MFA_REQUIRED"
    Then Mary should see an interaction_required error message
