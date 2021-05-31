Feature: 0.1 Root page for Direct Auth Demo Application

  Scenario: 0.1.1 Mary visits the Root View WITHOUT an authentication session
    Given Mary navigates to root page
    Then the Root Page shows links to the Entry Points