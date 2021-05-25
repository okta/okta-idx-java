package info.seleniumcucumber.userStepDefinitions;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.support.ui.ExpectedConditions;
import org.openqa.selenium.support.ui.WebDriverWait;

public class SelfServiceRegistration extends BasicDefinitions {

    @Given("Mary navigates to the Self Service Registration View")
    public void maryNavigatesToTheSelfServiceRegistrationView() {
        driver.manage().window().maximize();
        driver.get("http://localhost:8080");
        driver.findElement(By.id("register")).click();
    }

    @When("she fills out her First Name")
    public void sheFillsOutHerFirstName() {
        sleep();
        driver.findElement(By.name("firstname")).sendKeys("Mary");
    }

    @And("she fills out her Last Name")
    public void sheFillsOutHerLastName() {
        driver.findElement(By.name("lastname")).sendKeys("LastName");
    }

    @And("she fills out her Email with an invalid email format")
    public void sheFillsOutHerEmailWithAnInvalidEmailFormat() {
        driver.findElement(By.name("email")).sendKeys("invalid@acme");
    }

    @And("she submits the registration form")
    public void sheSubmitsTheRegistrationForm() {
        driver.findElement(By.id("sign-in-btn")).click();
    }

    @Then("she sees an error message \"'Email' must be in the form of an email address, Provided value for property 'Email' does not match required pattern\"")
    public void sheSeesAnErrorMessage() {
        sleep();
        By selection = By.className("alert-danger");
        (new WebDriverWait(driver, 30)).until(
                ExpectedConditions.visibilityOfElementLocated(selection));
        String error = driver.findElement(By.className("alert-danger")).getText();
        Assert.assertFalse("Error is not shown", error.isEmpty());
        Assert.assertTrue("'Email' does not match required pattern error is shown",
                error.contains("['Email' must be in the form of an email address, Provided value for property 'Email' does not match required pattern]"));
    }
}
