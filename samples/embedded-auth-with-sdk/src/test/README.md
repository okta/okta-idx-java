# Cucumber E2E Tests

The cucumber E2E tests are run automatically as part of the build. These tests use selenium webdriver to run tests against chrome browser.
To run the tests locally, we need to first run the following script from the root directory

```
cd okta-idx-java
./src/ci/download_chromedriver.sh
```
This will download the chromedriver binary based on your chrome version and place it in the `embedded-auth-with-sdk` directory.
Make sure the binary `chromedriver` is present in `samples/embedded-auth-with-sdk` after running the script

Next, we need to set some environment variables to run the tests. Variable names are self-explanatory
For example,
```
export USERNAME=mary@acme.com
export PASSWORD=SuperSecret123 
```
We assume all accounts use the same password. 

Apart from these, we'd of course need to set the variables needed to run the sample application itself
For example,
```
export OKTA_IDX_ISSUER=https://dev-1234.okta.com/oauth2/default
export OKTA_IDX_CLIENTID=xxxxxx
export OKTA_IDX_CLIENTSECRET=xxxxxx
export OKTA_IDX_SCOPES="openid email profile offline_access"
export OKTA_IDX_REDIRECTURI=http://localhost:8080/authorization-code/callback
export A18N_API_KEY=xxxxxx
export OKTA_CLIENT_ORGURL=https://dev-1234.okta.com
export OKTA_CLIENT_TOKEN=<org-api-token>
```

Now we're ready to run the tests
```
cd samples/embedded-auth-with-sdk
mvn verify
```

> NOTE: If you only want to run a specific test, comment out other scenarios in the `.feature` files. 
> It'll be clear once you see what the feature file contains on what we mean by this.

> To get the tests passing on local machine, you MUST include "offline_access" in the scope. See `OKTA_IDX_SCOPES` environment variable above.
> This is needed because tests check if `refresh_token` is returned from the server.

## How to write tests

Cucumber tests contain feature files that describe a specific feature and the corresponding scenarios in it.
These feature files are written in Gherkin Syntax which is a human-readable language to define Cucumber’s test cases.
The steps in the feature files are then automated in step definition files using selenium webdriver.

Here's an example of the login feature file - [login.feature](resources/features/login.feature). 
Here's the corresponding implementation in a step definition file - [Login.java](java/info/seleniumcucumber/userStepDefinitions/Login.java)

You can write new feature files and add the corresponding automation in the step definition files.
Happy coding!
