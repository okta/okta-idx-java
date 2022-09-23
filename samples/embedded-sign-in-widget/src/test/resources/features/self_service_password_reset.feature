
Feature: 8.2: Password Recovery with Embedded Sign In Widget

  @requireA18NProfile
  @requireExistingUser
  Scenario: 8.2.1 Mary resets the Password through forgot password link
    Given Mary navigates to the Embedded Widget View
    When she clicks on the Forgot Password link
    Then she sees the page to input the email address
    When she inputs her correct email address
    And she submits the recovery form
    And she sees a page saying "Verify with your email"
    Then she clicks on "Send me an email"
    And  the page changes to waiting screen message for email verification
    And she clicks on "Enter a code from the email instead"
    Then she sees a page to input her code
    When she fills in the correct code
    And she submits the form
    Then she sees a page to set her password
    When she fills a password that fits within the password policy
    And she confirms that password
    And she submits the password reset form
    Then she is redirected to the Root View
    And she sees a table with her profile info