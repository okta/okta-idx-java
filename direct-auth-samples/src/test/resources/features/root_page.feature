Feature: 0.1 Root page for Direct Auth Demo Application

  Scenario: 0.1.1 Mary visits the Root View WITHOUT an authentication session
    Given Mary navigates to root page
    Then the Root Page shows links to the Entry Points

  Scenario: 0.1.2 Mary visits the Root View WITHOUT an authentication session
    Given Mary has an authenticated session
    Then Mary sees a table with the claims from the userinfo response
    And Mary sees a logout button

  Scenario: 0.1.3 Mary visits the Root View WITHOUT an authentication session
    Given Mary has an authenticated session
    And Mary navigates to root page
    When Mary clicks the logout button
    Then she is redirected back to the Root View
    And Mary sees login, registration buttons
    And she does not see claims from /userinfo
