Feature: 10.4 Multi-Factor Authentication with Password and Security Question

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  Scenario: 10.4.1 Mary signs up for an account and enrolls in Password and a predefined Security Question
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    Then she sees a list of required factors to setup
    When she selects Password
    Then she sees a page to setup password
    When she fills out her Password
    And she confirms her Password
    And she submits the verify form
    Then she sees a page to input a code
    When she inputs the correct code from her email
    And she submits the verify form
    When she selects Security Question from the list
    And she selects a predefined Security Question
    And she enters "Okta" as the answer
    And she submits the form
    Then she sees the list of optional factors
    When she selects "Skip" on authenticators
    Then she is redirected to the Root View
    And an application session is created

  @requireA18NProfile
  @requireUserDeletionAfterRegistration
  Scenario: 10.4.2 Mary signs up for an account and enrolls in Password and a custom Security Question
    Given Mary navigates to the Self Service Registration View
    When she fills out her First Name
    And she fills out her Last Name
    And she fills out her Email
    And she submits the registration form
    Then she sees a list of required factors to setup
    When she selects Password
    Then she sees a page to setup password
    When she fills out her Password
    And she confirms her Password
    And she submits the verify form
    Then she sees a page to input a code
    When she inputs the correct code from her email
    And she submits the verify form
    When she selects Security Question from the list
    And she selects a custom Security Question
    And she enters "Okta" as the answer
    And she submits the form
    Then she sees the list of optional factors
    When she selects "Skip" on authenticators
    Then she is redirected to the Root View
    And an application session is created

  @requireA18NProfile
  @requireExistingUser
  @requireMFAGroupsForUser
  Scenario: 10.4.3 Mary Logs into the Sample App and enrolls in a predefined Security Question
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she fills in her correct password for mfa
    And she submits the Login form
    Then she is presented with a list of factors
    When she selects Security Question from the list
    And she selects a predefined Security Question
    And she enters "Okta" as the answer
    And she submits the form
    Then she sees the list of optional factors
    When she selects "Skip" on authenticators
    Then she is redirected to the Root View
    And an application session is created

  @requireA18NProfile
  @requireExistingUser
  @requireMFAGroupsForUser
  Scenario: 10.4.4 Mary Logs into the Sample App and enrolls in a custom Security Question
    Given Mary navigates to the Basic Login View
    When she fills in her correct username for mfa
    And she fills in her correct password for mfa
    And she submits the Login form
    Then she is presented with a list of factors
    When she selects Security Question from the list
    And she selects a custom Security Question
    And she enters "Okta" as the answer
    And she submits the form
    Then she sees the list of optional factors
    When she selects "Skip" on authenticators
    Then she is redirected to the Root View
    And an application session is created
