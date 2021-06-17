Feature: 5.1 Direct Auth Social Login with 1 Social IDP

  Scenario: 5.1.1 Mary Logs in with Social IDP
    Given Mary navigates to the Basic Login View
    When she clicks the "Login with Facebook" button
    And logs in to Facebook with USERNAME_FACEBOOK and PASSWORD_FACEBOOK
    Then she is redirected to the Root View
    And the cell for the value of "email" is shown and contains her USERNAME_FACEBOOK
    And the cell for the value of "name" is shown and contains her first name and last name
