Feature: Login
  As a user I should able to login into my app

  Scenario: I login with valid credential
    Given I navigate to "http://localhost:8080"
    And I enter "mary@acme.com" into input field having id "username"
    And I enter "Abcd1234" into input field having id "password"
    When I click on element having id "sign-in-btn"
    Then I should get logged-in

  Scenario: Close browser
    Then I close browser