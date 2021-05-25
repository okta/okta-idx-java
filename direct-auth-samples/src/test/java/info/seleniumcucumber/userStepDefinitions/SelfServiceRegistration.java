package info.seleniumcucumber.userStepDefinitions;

import cucumber.api.java.en.And;
import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import org.openqa.selenium.By;

public class SelfServiceRegistration extends BasicDefinitions {

    @Then("she sees a page to input her code1")
    public void sheSeesAPageToInputHerCode1() {
        sleep();
        driver.findElement(By.id("proceed-btn")).click();
    }

    @Given("Mary navigates to the Self Service Registration View")
    public void maryNavigatesToTheSelfServiceRegistrationView() {
    }

    @When("she fills out her First Name")
    public void sheFillsOutHerFirstName() {
    }

    @And("she fills out her Last Name")
    public void sheFillsOutHerLastName() {
    }

    @And("she fills out her Email")
    public void sheFillsOutHerEmail() {
    }

    @And("she fills out her Password")
    public void sheFillsOutHerPassword() {
    }

    @And("she confirms her Password")
    public void sheConfirmsHerPassword() {
    }

    @And("she submits the registration form")
    public void sheSubmitsTheRegistrationForm() {
    }
}
