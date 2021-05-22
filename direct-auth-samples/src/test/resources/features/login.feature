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
    Then she should see authentication failed error

  Scenario: Mary is not assigned to the application
    When she enters valid credentials for unassigned user
    And  she submits the Login form
    Then she should see user not assigned to app error

  Scenario: Mary's account is suspended
    When she enters valid credentials for suspended user
    And  she submits the Login form
    Then she should see authentication failed error

  Scenario: Mary's account is locked
    When she enters valid credentials for locked user
    And  she submits the Login form
    Then she should see authentication failed error

  Scenario: Mary's account is deactivated
    When she enters valid credentials for deactivated user
    And  she submits the Login form
    Then she should see user not assigned to app error

  Scenario: Tests completed. Close browser
    Then I close browser
