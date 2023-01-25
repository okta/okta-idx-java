Feature: 10.3 Okta Verify Enrollment with SMS and Email

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  Scenario: 10.3.1 Mary signs up for an account and enrolls in Password and scans QR code to enroll Okta Verify
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
    When she selects okta verify from the list
    Then she sees a page with QR code displayed for scanning

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  Scenario: 10.3.2 Mary signs up for an account and enrolls in Password and clicks a link in a text message to enroll Okta Verify
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
    When she selects okta verify from the list
    And  she sees the option "Can't scan"
    When she clicks on "Can't scan"
    Then she sees a list of modes to register
    When she selects SMS option
    And she submits the verify form
    Then she sees a page to input the phone number
    And she inputs a valid phone number for Okta verify
    And she clicks on submit button saying "Send me the setup link"
    Then the screen changes to a waiting screen saying "We sent an SMS with an Okta Verify setup link. To continue, open the link on your mobile device."
    When she clicks the link in her text messages from her phone
    Then she sees the download okta verify screen

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  Scenario: 10.3.3 Mary signs up for an account and enrolls in Password and clicks a link in an email message to enroll Okta Verify
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
    When she selects okta verify from the list
    And  she sees the option "Can't scan"
    When she clicks on "Can't scan"
    Then she sees a list of modes to register
    When she selects Email option
    Then she sees a page to input the Email
    And she fills out her Email for Okta verify
    And she clicks on submit button saying "Send me the setup link"
    Then the screen changes to a waiting screen saying "We sent an email with an Okta Verify setup link. To continue, open the link on your mobile device."
    When she clicks on the link in her email
    Then she sees the download okta verify screen

  @requireA18NProfile
  @requireExistingUser
  @requireMFAGroupsForUser
  @requireTOTPGroupForUser
  Scenario: 10.3.4 Mary signs in an account and enrolls in Password and scans QR code to enroll Okta Verify
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she fills in her correct password for mfa
    And she submits the Login form
    Then she is presented with an option to select Okta Verify
    When she selects okta verify
    Then she sees a page with QR code displayed for scanning