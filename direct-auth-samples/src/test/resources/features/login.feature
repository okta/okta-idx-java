Feature: Login
  As a user, Mary should be able to login into the app and access her profile

  Scenario: Mary logs in with a Password
    Given Mary navigates to the Basic Login View
    When she fills in her correct username
    And she fills in her correct password
    And she submits the Login form
    Then she is redirected to the Root View
    And the access_token is stored in session
    And the id_token is stored in session
    And the refresh_token is stored in session

  Scenario: Mary doesn't know her username
    Given Mary navigates to the Basic Login View
    When she fills in her incorrect username
    And she fills in her correct password
    And she submits the Login form
    Then she should see a "There is no account with username" message on the Login form

  Scenario: Mary doesn't know her password
    Given Mary navigates to the Basic Login View
    When she fills in her correct username
    And she fills in her incorrect password
    And she submits the Login form
    Then she should see the message "Authentication failed"

# If profile enrollment policy allows for self-service registration, this scenario doesn't work
# Clarified with IDX Team that this is expected behavior.
# TODO - Find a way to automate this scenario
#  Scenario: Mary is not assigned to the application
#  Given the Sample App is assigned to a "Certain" group
#  And   Mary is not a member of the "Certain" group
#  And   Mary navigates to the Basic Login View
#  When  she fills in her username
#  And   she fills in her correct password
#  And   she submits the Login form
#  Then  she sees the login form again with blank fields
#  And   should see the message "User is not assigned to this application"

  Scenario: Mary's account is suspended
    Given Mary's account is suspended
    And Mary navigates to the Basic Login View
    When she fills in her suspended username
    And she fills in her correct password
    And she submits the Login form
    Then she should see the message "Authentication failed"

  Scenario: Mary's account is locked
    Given Mary's account is locked
    And Mary navigates to the Basic Login View
    When she fills in her locked username
    And she fills in her correct password
    And  she submits the Login form
    Then she should see the message "Authentication failed"

  Scenario: Mary's account is deactivated
    Given Mary's account is deactivated
    And Mary navigates to the Basic Login View
    When she fills in her deactivated username
    And she fills in her correct password
    And  she submits the Login form
    Then she should see the message "Authentication failed"

  Scenario: Mary clicks on the "Forgot Password Link"
    Given Mary navigates to the Basic Login View
    When she clicks on the "Forgot Password Link"
    Then she is redirected to the Self Service Password Reset View

  Scenario: Tests completed. Close browser
    Then I close browser
