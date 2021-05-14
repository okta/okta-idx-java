package info.seleniumcucumber.userStepDefintions;
import cucumber.api.java.en.And;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.WebDriver;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

import cucumber.api.java.en.Given;
import env.DriverUtil;

public class UserStepDefinitions {
	
	protected WebDriver driver = DriverUtil.getDefaultDriver();

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
		driver.findElement(By.name("username")).sendKeys("mary@acme.com");
		driver.findElement(By.name("password")).sendKeys("Abcd1234");
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
		Assert.assertTrue("Can't access profile information", email.contains("mary@acme.com"));
	}

	@When("^she fills in her incorrect username with password$")
	public void enter_invalid_username() throws Throwable
	{
		driver.findElement(By.name("username")).sendKeys("invalid@acme.com");
		driver.findElement(By.name("password")).sendKeys("Abcd1234");
	}

	@Then("^she should see invalid user error$")
	public void invalid_user_error() throws Throwable {
		By selection = By.className("alert-danger");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String error = driver.findElement(By.className("alert-danger")).getText();
		Assert.assertTrue("Error is not shown", !error.isEmpty());
	}

	@When("^she fills in her correct username with incorrect password$")
	public void enter_valid_username_invalid_password() throws Throwable
	{
		driver.findElement(By.name("username")).sendKeys("mary@acme.com");
		driver.findElement(By.name("password")).sendKeys("invalid123");
	}

	@Then("^she should see incorrect password error$")
	public void incorrect_password_error() throws Throwable {
		By selection = By.className("alert-danger");
		(new WebDriverWait(driver, 30)).until(
				ExpectedConditions.visibilityOfElementLocated(selection));
		String error = driver.findElement(By.className("alert-danger")).getText();
		Assert.assertTrue("Error is not shown", !error.isEmpty());
		Assert.assertTrue("Incorrect password error is not shown'", error.contains("Password is incorrect"));
	}

}
