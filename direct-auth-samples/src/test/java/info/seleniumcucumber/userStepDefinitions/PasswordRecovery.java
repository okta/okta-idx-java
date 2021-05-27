package info.seleniumcucumber.userStepDefinitions;

import cucumber.api.java.en.And;
import cucumber.api.java.en.Given;
import cucumber.api.java.en.Then;
import cucumber.api.java.en.When;
import org.junit.Assert;
import org.openqa.selenium.By;

public class PasswordRecovery extends BasicDefinitions {

    @Given("an org with an ORG Policy that defines Authenticators with Password and Email as required")
    public void anOrgWithAnORGPolicyThatDefinesAuthenticatorsWithPasswordAndEmailAsRequired() {

    }

    @And("a user named \"Mary\"")
    public void AUserNamedMary() {

    }

    @And("Mary is a user with a verified email and a set password")
    public void MaryIsAUserWithAVerifiedEmailAndASetPassword() {

    }

    @Given("Mary navigates to the Self Service Password Reset View")
    public void maryNavigatesToTheSelfServicePasswordResetView() {
        driver.manage().window().maximize();
        driver.findElement(By.id("forgot-password")).click();
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

    @When("she fills in the correct code")
    public void sheFillsInTheCorrectCode() {
    }

    @And("she submits the form")
    public void sheSubmitsTheForm() {
        driver.findElement(By.id("next-btn")).click();
    }

    @Then("she sees a page to set her password")
    public void sheSeesAPageToSetHerPassword() {
    }

    @When("she fills a password that fits within the password policy")
    public void sheFillsAPasswordThatFitsWithinThePasswordPolicy() {
    }

    @And("she confirms that password")
    public void sheConfirmsThatPassword() {
    }

    @Then("a success message appears")
    public void aSuccessMessageAppears() {
    }

    @And("a link to the Root Page is provided")
    public void aLinkToTheRootPageIsProvided() {
    }

    @When("she selects \"Forgot Password\"")
    public void sheSelects() {
    }

    @Then("she sees the Password Recovery Page")
    public void sheSeesThePasswordRecoveryPage() {
        Assert.assertTrue("URL should ends with \"/forgot-password\"", driver.getCurrentUrl().endsWith("/forgot-password"));
        Assert.assertEquals("Wrong page title", "Forgot Password", driver.getTitle());
    }

    @When("she inputs an Email that doesn't exist")
    public void sheInputsAnEmailThatDoesnTExist() {
        driver.findElement(By.name("username")).sendKeys("example@mail.com");
    }

    @Then("she sees a message \"There is no account with the Username. Sign up for an account\"")
    public void sheSeesAMessage() {
        String error = driver.findElement(By.className("alert-danger")).getText();
        Assert.assertFalse("Error is not shown", error.isEmpty());
        Assert.assertTrue("Wrong error message is shown", error.contains("There is no account with the Username. Sign up for an account"));
    }
}
