Feature: 10.1 TOTP Support Google Authenticator

  @requireA18NProfile
  @requireExistingUser
  @requireMFAGroupsForUser
  @requireTOTPGroupForUser
  Scenario: 10.1.1 Mary signs in to an account and enrolls Google Authenticator by scanning a QR Code
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she fills in her correct password for mfa
    And she submits the Login form
    Then she sees the list of required factors (Google Authenticator) to enroll
    When she selects Google Authenticator from the list
    Then she sees a screen which shows a QR code and a shared secret key
    And she scans a QR Code
    And she selects "Next"
    Then the screen changes to receive an input for a code
    When she inputs the correct code from her Google Authenticator App
    And she submits the verify form
    Then she sees the list of optional factors
    When she selects "Skip" on authenticators
    Then she is redirected to the Root View
    And the cell for the value of "email" is shown and contains her email for mfa
    And the cell for the value of "name" is shown and contains her first name and last name
    And an application session is created

  @requireA18NProfile
  @requireExistingUser
  @requireMFAGroupsForUser
  @requireTOTPGroupForUser
  Scenario: 10.1.2 Mary signs in to an account and enrolls in Google Authenticator by entering a Secret Key
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she fills in her correct password for mfa
    And she submits the Login form
    Then she sees the list of required factors (Google Authenticator) to enroll
    When she selects Google Authenticator from the list
    Then she sees a screen which shows a QR code and a shared secret key
    And she enters the shared Secret Key into the Google Authenticator App
    And she selects "Next" on the screen which is showing the QR code
    Then the screen changes to receive an input for a code
    When she inputs the correct code from her Google Authenticator App
    And she submits the verify form
    Then she sees the list of optional factors
    When she selects "Skip" on authenticators
    Then she is redirected to the Root View
    And the cell for the value of "email" is shown and contains her email for mfa
    And the cell for the value of "name" is shown and contains her first name and last name
    And an application session is created

  # Test failing with error "Each code can only be used once. Please wait for a new code and try again."
  @ignore
  @requireA18NProfile
  @requireExistingUser
  @requireMFAGroupsForUser
  @requireEnrolledGoogleQR
  Scenario: 10.1.3 Mary Signs in to the Sample App with Password and Google Authenticator
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she fills in her correct password for mfa
    And she submits the Login form
    Then she is presented with an option to select Google Authenticator to verify
    When she selects Google Authenticator from the list
    Then the screen changes to receive an input for a code
    When she inputs the correct code from the Google Authenticator
    And she submits the verify form
    Then she is redirected to the Root View
    And the cell for the value of "email" is shown and contains her email for mfa
    And the cell for the value of "name" is shown and contains her first name and last name
    And an application session is created

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  Scenario: 10.1.4 Mary signs up for an account with Password, setups up required Google Authenticator by scanning a QR Code
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
# ENG_REMEMBER_LAST_USED_FACTOR_OIE feature avoids these steps
#    Then she sees the list of optional factors
#    When she selects Email
    Then she sees a page to input a code
    When she inputs the correct code from her email
    And she submits the verify form
    Then she sees the list of optional factors
    When she selects Google Authenticator from the list
    Then she sees a screen which shows a QR code and a shared secret key
    And she scans a QR Code
    And she selects "Next"
    Then the screen changes to receive an input for a code
    When she inputs the correct code from her Google Authenticator App
    And she submits the verify form
    When she selects "Skip" on SMS
    Then she is redirected to the Root View
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains Mary E2E-Java
    And an application session is created

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  Scenario: 10.1.5 Mary signs up for an account with Password, setups up required Google Authenticator by entering a shared secret
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
# ENG_REMEMBER_LAST_USED_FACTOR_OIE feature avoids these steps
#    Then she sees the list of optional factors
#    When she selects Email
    Then she sees a page to input a code
    When she inputs the correct code from her email
    And she submits the verify form
    Then she sees the list of optional factors
    When she selects Google Authenticator from the list
    Then she sees a screen which shows a QR code and a shared secret key
    And she enters the shared Secret Key into the Google Authenticator App
    And she selects "Next" on the screen which is showing the QR code
    Then the screen changes to receive an input for a code
    When she inputs the correct code from her Google Authenticator App
    And she submits the verify form
    When she selects "Skip" on SMS
    Then she is redirected to the Root View
    And the cell for the value of "email" is shown and contains her email
    And the cell for the value of "name" is shown and contains Mary E2E-Java
    And an application session is created
