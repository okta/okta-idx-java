package info.seleniumcucumber.userStepDefinitions;

import io.cucumber.java.en.And;
import io.cucumber.java.en.Given;
import io.cucumber.java.en.Then;
import io.cucumber.java.en.When;
import org.openqa.selenium.By;

public class PasswordRecovery extends BasicDefinitions {

    @Given("Mary navigates to the Self Service Password Reset View")
    public void maryNavigatesToTheSelfServicePasswordResetView() {
        driver.manage().window().maximize();
        driver.get("http://localhost:8080/forgot-password");
    }

    @When("she inputs her correct Email")
    public void sheInputsHerCorrectEmail() {
        sleep();
        driver.findElement(By.name("username")).sendKeys(USERNAME);
    }

    @And("she submits the recovery form")
    public void sheSubmitsTheRecoveryForm() {
        driver.findElement(By.id("next-btn")).click();
    }

    @Then("she sees a page to input her code")
    public void sheSeesAPageToInputHerCode() {
        sleep();
        driver.findElement(By.id("proceed-btn")).click();
    }
}
