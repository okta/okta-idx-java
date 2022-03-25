/*
 * Copyright (c) 2021-Present, Okta, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package info.seleniumcucumber.userStepDefinitions;

import com.okta.sdk.client.Clients;
import com.okta.sdk.resource.user.User;
import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import env.CucumberRoot;
import env.DriverUtil;

import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.ForgotPasswordPage;
import pages.LoginPage;
import pages.Page;
import pages.RootPage;

public class Login extends CucumberRoot {

	protected WebDriver driver = DriverUtil.getDefaultDriver();
	private RootPage rootPage = new RootPage(driver);
	private LoginPage loginPage = new LoginPage(driver);
	private ForgotPasswordPage forgotPasswordPage = new ForgotPasswordPage(driver);
	private User user;

	@When("^she fills in her correct username$")
	public void enter_correct_username() {
		loginPage.waitForWebElementDisplayed(loginPage.usernameInput);
		loginPage.usernameInput.click();
		loginPage.usernameInput.sendKeys(USERNAME);
	}

	@And("^she fills in her correct password$")
	public void enter_correct_password() {
		loginPage.passwordInput.click();
		loginPage.passwordInput.sendKeys(PASSWORD);
	}

	@And("^she submits the Login form$")
	public void clicks_login_button() {
		loginPage.signInButton.click();
	}

	@Then("^she is redirected to the Root View$")
	public void redirected_to_root_view() {
		rootPage.waitForWebElementDisplayed(rootPage.profileTable);
		Assert.assertTrue("Can't access profile information", rootPage.profileTable.isDisplayed());
	}

	@And("^the access_token is stored in session$")
	public void access_token_stored() {
		rootPage.waitForWebElementDisplayed(rootPage.accessToken);
		Assert.assertTrue(rootPage.accessToken.isDisplayed());
		String accessToken = rootPage.accessToken.getText();
		Assert.assertFalse("Can't access access_token", accessToken.isEmpty());
	}

	@And("^the id_token is stored in session$")
	public void id_token_stored() {
		rootPage.waitForWebElementDisplayed(rootPage.idToken);
		Assert.assertTrue(rootPage.idToken.isDisplayed());
		String idToken = rootPage.idToken.getText();
		Assert.assertFalse("Can't access id_token", idToken.isEmpty());
	}

	@And("^the refresh_token is stored in session$")
	public void refresh_token_stored() {
		rootPage.waitForWebElementDisplayed(rootPage.refreshToken);
		Assert.assertTrue(rootPage.refreshToken.isDisplayed());
		String refreshToken = rootPage.refreshToken.getText();
		Assert.assertFalse("Can't access refresh_token", refreshToken.isEmpty());
	}

	@And("the cell for the value of \"email\" is shown and contains {word}")
	public void the_cell_for_email_is_shown_and_contains_her_email(String email) {
		Assert.assertTrue(rootPage.email.isDisplayed());
		Assert.assertEquals(System.getenv(email), rootPage.email.getText());
		user = getUser(System.getenv(email));
	}

	@And("^the cell for the value of \"email\" is shown and contains her email$")
	public void the_cell_for_email_is_shown_and_contains_her_email() {
		Assert.assertTrue(rootPage.email.isDisplayed());
		Assert.assertEquals(Page.getA18NProfile().getEmailAddress(), rootPage.email.getText());
	}

	@And("^the cell for the value of \"email\" is shown and contains her email for mfa$")
	public void the_cell_for_email_is_shown_and_contains_her_email_for_mfa() {
		Assert.assertTrue(rootPage.email.isDisplayed());
		Assert.assertEquals(Page.getUser().getProfile().getEmail(), rootPage.email.getText());
		user = Page.getUser();
	}

	@And("the cell for the value of \"name\" is shown and contains {word} {word}")
	public void the_cell_for_name_is_shown_and_contains_her_name(String name, String surname) {
		Assert.assertTrue(rootPage.name.isDisplayed());
		Assert.assertEquals(name + " " + surname + "-" + Page.getA18NProfile().getProfileId(), rootPage.name.getText());
	}

	@And("^the cell for the value of \"name\" is shown and contains her first name and last name$")
	public void the_cell_for_name_is_shown_and_contains_her_name_for_mfa() {
		Assert.assertTrue(rootPage.name.isDisplayed());
		Assert.assertTrue(rootPage.name.getText().contains(user.getProfile().getFirstName()));
		Assert.assertTrue(rootPage.name.getText().contains(user.getProfile().getLastName()));
	}

	@When("^she fills in her incorrect username$")
	public void enter_incorrect_username() {
		loginPage.waitForWebElementDisplayed(loginPage.usernameInput);
		loginPage.usernameInput.click();
		loginPage.usernameInput.sendKeys("invalid@acme.com");
	}

	@Then("^she should see a \"There is no account with username\" message on the Login form$")
	public void no_account_user_error() {
		rootPage.waitForWebElementDisplayed(rootPage.alertDanger);
		Assert.assertTrue(rootPage.alertDanger.isDisplayed());
		String error = rootPage.alertDanger.getText();
		Assert.assertFalse("Error is not shown", error.isEmpty());
		// If sign-up is enabled for the app, we see the account doesn't exist error
		Assert.assertTrue("No account with username error is not shown'",
				error.contains("There is no account with the Username"));
	}

	@When("^she fills in her incorrect password$")
	public void enter_incorrect_password() {
		loginPage.passwordInput.click();
		loginPage.passwordInput.sendKeys("invalid123");
	}

	@Then("^she should see the message \"Authentication failed\"$")
	public void authentication_failed_message() {
		rootPage.waitForWebElementDisplayed(rootPage.alertDanger);
		Assert.assertTrue(rootPage.alertDanger.isDisplayed());
		String error = rootPage.alertDanger.getText();
		Assert.assertFalse("Error is not shown", error.isEmpty());
		// Depending on whether user enumeration is enabled/disabled different errors are seen
		// It's enough if we verify that any error is shown (since it's returned by backend)
		// Assert.assertTrue("Authentication failed error is not shown'",
		// 		error.contains("Authentication failed"));
	}

	@When("^she clicks on the \"Forgot Password Link\"$")
	@When("^she selects \"Forgot Password\"$")
	public void clicks_forgot_password_link() {
		loginPage.waitForWebElementDisplayed(loginPage.forgotPasswordLink);
		Assert.assertTrue(loginPage.forgotPasswordLink.isDisplayed());
		loginPage.forgotPasswordLink.click();
	}

	@Then("^she is redirected to the Self Service Password Reset View$")
	public void redirect_to_sspr_view() {
		forgotPasswordPage.waitForWebElementDisplayed(forgotPasswordPage.forgotPasswordForm);
		Assert.assertTrue(forgotPasswordPage.forgotPasswordForm.isDisplayed());
		Assert.assertEquals(forgotPasswordPage.getCurrentUrl(), "http://localhost:8080/forgot-password");
	}

	@Given("^Mary has an authenticated session$")
	public void mary_has_an_authenticated_session() {
		rootPage.navigateToTheRootPage();
		rootPage.loginButton.click();

		loginPage.waitForWebElementDisplayed(loginPage.usernameInput);
		loginPage.usernameInput.click();
		loginPage.usernameInput.sendKeys(USERNAME);

		loginPage.passwordInput.click();
		loginPage.passwordInput.sendKeys(PASSWORD);
		loginPage.signInButton.click();
	}

	@Then("^Mary sees a table with the claims from the userinfo response$")
	public void mary_sees_a_table_with_the_claims_from_the_userinfo_response() {
		Assert.assertTrue(rootPage.idToken.isDisplayed());
		Assert.assertTrue(rootPage.refreshToken.isDisplayed());
		Assert.assertTrue(rootPage.profileTable.isDisplayed());
	}

	@And("^Mary sees a logout button$")
	public void mary_sees_a_logout_button() {
		rootPage.waitForWebElementDisplayed(rootPage.logoutButton);
		Assert.assertTrue(rootPage.logoutButton.isDisplayed());
	}

    private User getUser(String email) {
	    Assert.assertNotNull(email);
        return Clients.builder().build()
                .listUsers()
                .stream()
                .filter(user -> email.equals(user.getProfile().getEmail()))
                .findFirst()
                .orElse(null);
    }

}
