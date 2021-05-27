Feature: Login
  As a user, Mary should be able to login into the app and access her profile

  Scenario: 0.1.1 Mary visits the Root View WITHOUT an authentcation session
    Given Mary navigates to root page
    Then the Root Page shows links to the Entry Points