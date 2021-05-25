Feature: Self Service Registration
  As a user, Mary should be able to register

  Scenario: Mary signs up with an invalid Email
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she fills out her Password
    And she confirms her Password
    And she submits the registration form
    Then she sees an error message "'Email' must be in the form of an email address, Provided value for property 'Email' does not match required pattern"


