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
package info.seleniumcucumber.userStepDefintions;

import cucumber.api.java.en.And;
import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import env.CucumberRoot;
import env.DriverUtil;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

public class UserStepDefinitions extends CucumberRoot {
	
	protected WebDriver driver = DriverUtil.getDefaultDriver();
	private String USERNAME = System.getenv("USERNAME");
	private String PASSWORD = System.getenv("PASSWORD");

	@Given("^Mary navigates to the login page$")
	public void navigate_to_home_page() throws Throwable
	{
		driver.manage().window().maximize();
		driver.get("http://localhost:8080");
		driver.findElement(By.id("login")).click();
	}

	@When("^she enters valid credentials$")
	public void enter_valid_credentials() throws Throwable
	{
		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
		// The below block doesn't help either. Only sleep works. (╯°□°）╯︵ ┻━┻
		// new WebDriverWait(driver, 10).until(ExpectedConditions.elementToBeClickable(By.name("username"))).click();
		driver.findElement(By.name("username")).sendKeys(USERNAME);
		driver.findElement(By.name("password")).sendKeys(PASSWORD);
	}

	@And("^she submits the Login form$")
	public void clicks_login_button() throws Throwable {
		driver.findElement(By.id("sign-in-btn")).click();
	}
	
	@Then("^Mary should get logged-in$")
	public void should_logged_in() throws Throwable {
		By selection = By.id("profileTable");
        (new WebDriverWait(driver, 30)).until(
                ExpectedConditions.visibilityOfElementLocated(selection));
		String email = driver.findElement(By.id("email")).getText();
		Assert.assertTrue("Can't access profile information", email.contains(USERNAME));
	}

	@When("^she fills in her incorrect username with password$")
	public void enter_invalid_username() throws Throwable
	{
		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
		driver.findElement(By.name("username")).sendKeys("invalid@acme.com");
		driver.findElement(By.name("password")).sendKeys(PASSWORD);
	}

	@Then("^she should see invalid user error$")
	public void invalid_user_error() throws Throwable {
		By selection = By.className("alert-danger");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String error = driver.findElement(By.className("alert-danger")).getText();
		Assert.assertTrue("Error is not shown", !error.isEmpty());
		// TODO - In some orgs, we also see "you don't have permissions" error. Check why the difference.
		// Assert.assertTrue("Invalid username error is not shown'", error.contains("There is no account with the Username"));
	}

	@When("^she fills in her correct username with incorrect password$")
	public void enter_valid_username_invalid_password() throws Throwable
	{
		Thread.sleep(500); // Removing this fails the test. ¯\_(ツ)_/¯
		driver.findElement(By.name("username")).sendKeys(USERNAME);
		driver.findElement(By.name("password")).sendKeys("invalid123");
	}

	@Then("^she should see incorrect password error$")
	public void incorrect_password_error() throws Throwable {
		By selection = By.className("alert-danger");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String error = driver.findElement(By.className("alert-danger")).getText();
		Assert.assertTrue("Error is not shown", !error.isEmpty());
		Assert.assertTrue("Authentication failed error is not shown'", error.contains("Authentication failed"));
	}

	@Then("^I close browser$")
	public void close_browser() {
		driver.close();
	}

}
