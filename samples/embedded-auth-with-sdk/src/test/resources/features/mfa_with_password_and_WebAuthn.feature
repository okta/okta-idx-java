Feature: 4.4 Multi-Factor Authentication with Password and enrolls WebAuthn

  @requireA18NProfile
  @requireExistingUser
  @requireWebAuthnRequiredGroupsForUser
  Scenario: 4.4.1 Mary Logs into the Sample App and enrolls in WebAuthn
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she fills in her correct password for mfa
    And she submits the Login form
    Then she is presented with an option to select Email to verify
    When she selects Email
    Then she sees a page to input a code
    When she fills in the correct code
    And she submits the verify form
    Then she is presented with a list of factors
    Then she sees WebAuthn factor to register
    And she selects WebAuthn from the list
    And she inputs the fingerprint
    Then she sees the list of optional factors
    When she selects "Skip" on authenticators
    Then she is redirected to the Root View
    And an application session is created