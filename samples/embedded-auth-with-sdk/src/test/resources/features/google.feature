Feature: 7.1 Direct Auth with Self Hosted Sign In Widget Social Login with 1 Social IDP

  Scenario: 7.1.1 Mary Logs in with Social IDP
    Given Mary navigates to the Basic Login View
    When she clicks the "Login with Google" button in the embedded Sign In Widget
    And logs in to Google with USERNAME_GOOGLE and PASSWORD_GOOGLE
    Then she is redirected to the Root View
    And the cell for the value of "email" is shown and contains her USERNAME_GOOGLE
    And the cell for the value of "name" is shown and contains her first name and last name
