Feature: Login
  As a user, Mary should be able to login into the app and access her profile

  Background:
    Given Mary navigates to the login page

  Scenario: Mary logs in with a Password
    When she enters valid credentials
    And  she submits the Login form
    Then Mary should get logged-in

  Scenario: Mary doesn't know her username
    When she fills in her incorrect username with password
    And  she submits the Login form
    Then she should see invalid user error

  Scenario: Mary doesn't know her password
    When she fills in her correct username with incorrect password
    And  she submits the Login form
    Then she should see incorrect password error

  Scenario: Tests completed. Close browser
    Then I close browser
