Feature: Password Recovery
  As a user, Mary should be able to resets her password

  Scenario: Mary resets her password
    Given Mary navigates to the Self Service Password Reset View
    When she inputs her correct Email
    And  she submits the recovery form
    Then she sees a page to input her code