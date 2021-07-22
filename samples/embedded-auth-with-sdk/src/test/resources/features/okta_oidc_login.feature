Feature: 5.1 Direct Auth Social Login with 1 Social IDP

  Scenario: 5.1.1 Mary Logs in with Social IDP
    Given Mary navigates to the Basic Login View
    When she clicks the "Login with OIDC" button
    And logs in to OIDC IdP with USERNAME and PASSWORD
    Then she is redirected to the Root View
    And the cell for the value of "email" is shown and contains her USERNAME
    And the cell for the value of "name" is shown and contains her first name and last name
