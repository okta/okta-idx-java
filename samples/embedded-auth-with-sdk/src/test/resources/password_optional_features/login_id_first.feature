Feature: 1.2 Login with Identifier First
  As a user, Mary should be able to login into the app in Identifier First mode and access her profile

  @requireA18NProfile
  @requireExistingUser
  @requirePasswordOptionalGroupForUser
  @requireIDFirstPolicy
  @requireIDFirstPolicyDeletionAfterTest
  Scenario: 1.2.1 Mary logs in with Email with an OTP
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she submits the Login form
    Then she is presented with a list of factors
    When she selects Email
    Then she sees a page to input a code
    When she fills in the correct code
    And she submits the verify form
    Then she is redirected to the Root View
    And an application session is created

  @requireA18NProfile
  @requireExistingUser
  @requirePasswordOptionalGroupForUser
  @requireIDFirstPolicy
  @requireIDFirstPolicyDeletionAfterTest
  Scenario: 1.2.2 Mary Logs in with Email Magic Link on the same Browser
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she submits the Login form
    Then she is presented with a list of factors
    When she selects Email
    Then she sees a page to input a code
    When she opens the magic link in another tab
    Then she is redirected to the Root View
    And an application session is created

  @requireA18NProfile
  @requireExistingUser
  @requirePasswordOptionalGroupForUser
  @requireIDFirstPolicy
  @requireIDFirstPolicyDeletionAfterTest
  Scenario: 1.2.1 Mary Logs in with a Password
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she submits the Login form
    Then she is presented with a list of factors
    When she selects Password
    And she fills in her correct password
    And she submits the verify form
    Then she is redirected to the Root View
    And an application session is created
