Feature: Password Recovery
  As a user, Mary should be able to resets her password

  Background:
    Given Mary navigates to the login page

  Scenario: Mary resets her password
    Given Mary navigates to the Self Service Password Reset View
    When she inputs her correct Email
    And she submits the recovery form
    Then she sees a page to input her code
    When she fills in the correct code
    And she submits the form
    Then she sees a page to set her password
    When she fills a password that fits within the password policy
    And she confirms that password
    And she submits the form
    Then a success message appears
    And a link to the Root Page is provided

  Scenario: Mary tries to reset a password with the wrong email
    Given Mary navigates to the Self Service Password Reset View
    When she selects "Forgot Password"
    Then she sees the Password Recovery Page
    When she inputs an Email that doesn't exist
    And she submits the form
    Then she sees a message "There is no account with the Username {username}."
