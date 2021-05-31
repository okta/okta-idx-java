/*
 * Copyright 2021-Present Okta, Inc.
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

import cucumber.api.java.en.And;
import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import env.CucumberRoot;
import env.DriverUtil;

import org.junit.Assert;
import org.openqa.selenium.WebDriver;
import pages.ForgotPasswordPage;
import pages.LoginPage;
import pages.RootPage;

public class Login extends CucumberRoot {

	protected WebDriver driver = DriverUtil.getDefaultDriver();
	private RootPage rootPage = new RootPage(driver);
	private LoginPage loginPage = new LoginPage(driver);
	private ForgotPasswordPage forgotPasswordPage = new ForgotPasswordPage(driver);

	@When("^she fills in her correct username$")
	public void enter_correct_username() {
		loginPage.sleep();
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
		rootPage.sleep();
		Assert.assertTrue(rootPage.email.isDisplayed());
		String email = rootPage.email.getText();
		Assert.assertFalse("Can't access profile information", email.isEmpty());
	}

	@And("^the access_token is stored in session$")
	public void access_token_stored() {
		rootPage.sleep();
		Assert.assertTrue(rootPage.accessToken.isDisplayed());
		String accessToken = rootPage.accessToken.getText();
		Assert.assertFalse("Can't access access_token", accessToken.isEmpty());
	}

	@And("^the id_token is stored in session$")
	public void id_token_stored() {
		rootPage.sleep();
		Assert.assertTrue(rootPage.idToken.isDisplayed());
		String idToken = rootPage.idToken.getText();
		Assert.assertFalse("Can't access id_token", idToken.isEmpty());
	}

	@And("^the refresh_token is stored in session$")
	public void refresh_token_stored() {
		rootPage.sleep();
		Assert.assertTrue(rootPage.refreshToken.isDisplayed());
		String refreshToken = rootPage.refreshToken.getText();
		Assert.assertFalse("Can't access refresh_token", refreshToken.isEmpty());
	}

	@When("^she fills in her incorrect username$")
	public void enter_incorrect_username() {
		loginPage.sleep();
		loginPage.usernameInput.click();
		loginPage.usernameInput.sendKeys("invalid@acme.com");
	}

	@Then("^she should see a \"There is no account with username\" message on the Login form$")
	public void no_account_user_error() {
		rootPage.sleep();
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
		rootPage.sleep();
		Assert.assertTrue(rootPage.alertDanger.isDisplayed());
		String error = rootPage.alertDanger.getText();
		Assert.assertFalse("Error is not shown", error.isEmpty());
		Assert.assertTrue("Authentication failed error is not shown'",
				error.contains("Authentication failed"));
	}

	@When("^she clicks on the \"Forgot Password Link\"$")
	public void clicks_forgot_password_link() {
		loginPage.sleep();
		Assert.assertTrue(loginPage.forgotPasswordLink.isDisplayed());
		loginPage.forgotPasswordLink.click();
	}

	@Then("^she is redirected to the Self Service Password Reset View$")
	public void redirect_to_sspr_view() {
		forgotPasswordPage.sleep();
		Assert.assertTrue(forgotPasswordPage.forgotPasswordForm.isDisplayed());
		Assert.assertEquals(forgotPasswordPage.getCurrentUrl(), "http://localhost:8080/forgot-password");
	}

//	@When("^she enters valid credentials for unassigned user$")
//	public void enter_valid_credentials_for_unassigned_user() throws Throwable {
//		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
//		driver.findElement(By.name("username")).sendKeys(USERNAME_WITH_APP_UNASSIGNED);
//		driver.findElement(By.name("password")).sendKeys(PASSWORD);
//	}

//	@Then("^she should see user not assigned to app error$")
//	public void user_not_assigned_app_error() throws Throwable {
//		By selection = By.className("alert-danger");
//		(new WebDriverWait(driver, 30)).until(
//				ExpectedConditions.visibilityOfElementLocated(selection));
//		String error = driver.findElement(selection).getText();
//		Assert.assertTrue("Error is not shown", !error.isEmpty());
////		TODO: If Profile enrollment policy allows sign-up, this error in not shown. Commenting until we get clarity on this
////		Assert.assertTrue("User not assigned error is not shown", error.contains("User is not assigned to this application"));
//	}

//	@Given("^Mary's account is suspended$")
//	public void suspended_user() throws Throwable {
//		// This is a suspended user
//		System.out.println(USERNAME_SUSPENDED);
//	}

//	@When("^she fills in her suspended username$")
//	public void enter_suspended_username() throws Throwable {
//		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
//		// The below block doesn't help either. Only sleep works. (╯°□°）╯︵ ┻━┻
//		// new WebDriverWait(driver, 10).until(ExpectedConditions.elementToBeClickable(By.name("username"))).click();
//		driver.findElement(By.name("username")).sendKeys(USERNAME_SUSPENDED);
//	}

//	@Given("^Mary's account is locked")
//	public void locked_user() throws Throwable {
//		// This is a suspended user
//		System.out.println(USERNAME_LOCKED);
//	}

//	@When("^she fills in her locked username$")
//	public void enter_locked_username() throws Throwable {
//		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
//		// The below block doesn't help either. Only sleep works. (╯°□°）╯︵ ┻━┻
//		// new WebDriverWait(driver, 10).until(ExpectedConditions.elementToBeClickable(By.name("username"))).click();
//		driver.findElement(By.name("username")).sendKeys(USERNAME_LOCKED);
//	}

//	@Given("^Mary's account is deactivated")
//	public void deactivated_user() throws Throwable {
//		// This is a suspended user
//		System.out.println(USERNAME_DEACTIVATED);
//	}

//	@When("^she fills in her deactivated username$")
//	public void enter_deactivated_username() {
//		rootPage.sleep();
//		driver.findElement(By.name("username")).sendKeys(USERNAME_DEACTIVATED);
//	}

}
