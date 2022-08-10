Feature: 4.3 Self Service Registration with Email Activation And optional WebAuth

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  Scenario: 4.3.1 Mary signs up for an account with Password, enrolls Mail and Web Authentication
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    Then she sees a list of required factors to setup
    When she selects Password
    Then she sees a page to setup password
    When she fills out her Password
    And she confirms her Password
    And she submits the verify form
    Then she sees a page to input a code
    When she inputs the correct code from her email
    And she submits the verify form
    Then she sees a list of required factors to setup
    Then she sees WebAuthn factor to register
    And she selects WebAuthn from the list
    And she inputs the fingerprint
    Then she sees the list of optional factors
    When she selects "Skip" on authenticators
    And an application session is created
