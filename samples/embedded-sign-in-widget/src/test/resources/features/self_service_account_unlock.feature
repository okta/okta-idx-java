Feature: 8.3 Self service account unlock with with Single factor (Email, Phone, Okta Verify Push)

  @requireA18NProfile
  @requireExistingUser
  @requireMFAGroupsForUser
  Scenario: 8.3.1 Mary recovers from a locked account with Email Magic Link from a different Browser
    Given Mary navigates to the Embedded Widget View
    When she inputs her correct email address
    And she fills in her incorrect password
    And she submits the Login form and locks the account
    When she sees a link to unlock her account
    And she clicks the link to unlock her account
    Then she sees a page to input her username and select Email or Phone to unlock her account
    When she inputs her correct email address
    Then she selects Email from the available options
    And she sees a page saying "Verify with your email"
    Then she clicks on "Send me an email"
    And the page changes to waiting screen message for email verification
    And she clicks on "Enter a code from the email instead"
    Then she sees a page to input her code
    When she opens the magic link from her email inbox
    Then she sees a page that says "Account Successfully Unlocked!" and to enter the password for verification
    Given Mary navigates to the Embedded Widget View
    When she inputs her correct email address
    And she fills in her account password
    And she submits the Login form
    Then she is redirected to the Root View
    And she sees a table with her profile info

  @requireA18NProfile
  @requireExistingUser
  @requireMFAGroupsForUser
  Scenario: 8.3.2 Mary recovers from a locked account with Email OTP
    Given Mary navigates to the Embedded Widget View
    When she inputs her correct email address
    And she fills in her incorrect password
    And she submits the Login form and locks the account
    When she sees a link to unlock her account
    And she clicks the link to unlock her account
    Then she sees a page to input her username and select Email or Phone to unlock her account
    When she inputs her correct email address
    Then she selects Email from the available options
    And she sees a page saying "Verify with your email"
    Then she clicks on "Send me an email"
    And the page changes to waiting screen message for email verification
    And she clicks on "Enter a code from the email instead"
    Then she sees a page to input her code
    When she fills in the correct code
    And she submits the verify form
    Then she sees a page that says "Account Successfully Unlocked!" and to enter the password for verification
    And she fills in her account password
    And she submits the verify form
    Then she is redirected to the Root View
    And she sees a table with her profile info

  @requireA18NProfile
  @requireExistingUser
  @requireEnrolledPhone
  @requireMFAGroupsForUser
  Scenario: 8.3.3 Mary recovers from a locked account with SMS OTP
    Given Mary navigates to the Embedded Widget View
    When she inputs her correct email address
    And she fills in her incorrect password
    And she submits the Login form and locks the account
    When she sees a link to unlock her account
    And she clicks the link to unlock her account
    Then she sees a page to input her username and select Email or Phone to unlock her account
    When she inputs her correct email address
    Then she selects "Phone" from the available options
    And she sees a page saying "Verify with your phone"
    Then she clicks the button saying "Receive a code via SMS"
    Then she sees a page to input her code
    When she fills in the correct code from SMS
    And she submits the verify form
    Then she sees a page that says "Account Successfully Unlocked!" and to enter the password for verification
    And she fills in her account password
    And she submits the verify form
    Then she is redirected to the Root View
    And she sees a table with her profile info
