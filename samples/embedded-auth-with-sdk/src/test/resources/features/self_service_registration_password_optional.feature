# OKTA-497595 -Needs a different client_id to run
@ignore
Feature: 4.2 Self Service Registration with Email Activation And optional password
  
  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  @requireIDFirstPolicy
  @requireIDFirstPolicyDeletionAfterTest
  Scenario: 4.2.1 Mary signs up for an account with required Email factor, then skips optional password
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
  Scenario: 4.2.2 Mary signs up for an account with required Email factor, then enrolls optional password
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

