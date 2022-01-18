Feature: 10.1 TOTP Support Google Authenticator

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  Scenario: 10.1.1 Mary signs in to an account And enrolls in Password And Google Authenticator by scanning a QR Code
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
    Then she sees the list of optional factors
    When she selects Email
    Then she sees a page to input a code
    When she inputs the correct code from her email
    And she submits the verify form
    Then she sees the list of optional factors
    When she selects Google Authenticator from the list
    And she scans a QR Code
    And she selects "Next"
    Then the screen changes to receive an input for a code
    When she inputs the correct code from her Google Authenticator App
    And she submits the verify form
    When she selects "Skip" on SMS
    Then she is redirected to the Root View
    And an application session is created
