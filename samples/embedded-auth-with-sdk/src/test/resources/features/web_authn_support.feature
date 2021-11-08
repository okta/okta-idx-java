Feature: 10.2 WebAuthn support

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  Scenario: 10.2.1 Mary signs in to an account And enrolls in Password And Google Authenticator by scanning a QR Code
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
    When she selects Biometric from the list
    And she selects "Set up"
    Then she sees a prompt to select a Security Key or This Device
