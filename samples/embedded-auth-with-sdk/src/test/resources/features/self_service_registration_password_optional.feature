Feature: 1.2 Signup and login with Identifier First

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  @requireIDFirstPolicy
  @requireIDFirstPolicyDeletionAfterTest
  Scenario: 1.2.1 Mary signs up for an account with required Email factor, then skips optional password
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    Then she sees a page to input a code
    When she inputs the correct code from her email
    And she submits the verify form
    Then she sees the list of optional factors
    When she selects "Skip" on authenticators
    Then she is redirected to the Root View
    And an application session is created

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  @requireIDFirstPolicy
  @requireIDFirstPolicyDeletionAfterTest
  Scenario: 1.2.2 Mary signs up for an account with required Email factor, then enrolls optional password
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    Then she sees a page to input a code
    When she inputs the correct code from her email
    And she submits the verify form
    Then she sees the list of optional factors
    When she selects Password
    Then she sees a page to setup password
    When she fills out her Password
    And she confirms her Password
    And she submits the verify form
    Then she is redirected to the Root View
    And an application session is created

  @requireA18NProfile
  @requireExistingUser
  @requirePasswordOptionalGroupForUser
  @requireIDFirstPolicy
  @requireIDFirstPolicyDeletionAfterTest
  Scenario: 1.2.3 2FA Login with Email
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she submits the Login form
    Then she is presented with an option to select Email to verify
    When she selects Email
    Then she sees a page to input a code
    When she fills in the correct code
    And she submits the verify form
    Then she is redirected to the Root View
    And an application session is created
