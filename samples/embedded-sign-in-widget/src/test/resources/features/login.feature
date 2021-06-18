Feature: 8.1: Basic Login with Embedded Sign In Widget

  Scenario: 8.1.1 Mary logs in with a Password
    Given Mary navigates to the Embedded Widget View
    When she fills in her correct username
    And she fills in her correct password
    And she submits the Login form
    Then she is redirected to the Root View
    And she sees a table with her profile info
    And the cell for the value of "email" is shown and contains her USERNAME
