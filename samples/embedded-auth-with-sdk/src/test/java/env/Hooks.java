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
package env;

import com.okta.sdk.client.Client;
import com.okta.sdk.client.ClientBuilder;
import com.okta.sdk.client.Clients;
import com.okta.sdk.resource.group.Group;
import com.okta.sdk.resource.group.GroupList;
import com.okta.sdk.resource.policy.*;
import com.okta.sdk.resource.user.User;
import com.okta.sdk.resource.user.UserBuilder;
import com.okta.sdk.resource.user.factor.ActivateFactorRequest;
import com.okta.sdk.resource.user.factor.FactorProvider;
import com.okta.sdk.resource.user.factor.FactorType;
import com.okta.sdk.resource.user.factor.SmsUserFactor;
import com.okta.sdk.resource.user.factor.TokenUserFactor;
import com.okta.sdk.resource.user.factor.UserFactor;
import env.a18n.client.DefaultA18NClientBuilder;
import io.cucumber.java.After;
import io.cucumber.java.Before;
import io.cucumber.java.Scenario;
import org.junit.Assert;
import org.openqa.selenium.By;
import org.openqa.selenium.NoSuchElementException;
import org.openqa.selenium.WebDriver;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import pages.Page;
import pages.QrCodePage;

import java.util.*;
import java.util.stream.Collectors;

public class Hooks {

	private final Logger logger = LoggerFactory.getLogger(Hooks.class);

	protected WebDriver driver = DriverUtil.getDefaultDriver();
	protected ClientBuilder builder = Clients.builder();
	protected Client client = builder.build();

	@Before
	public void beforeScenario(){
		System.out.println("This will run before each Scenario");
	}

	@After
	public void afterScenario(){
		System.out.println("This will run after each Scenario");

		if (isAlive() && existsElement("logout-btn")) {
			driver.findElement(By.id("logout-btn")).click();
		}
		DriverUtil.closeDriver();
	}

	@Before(order = 0, value = "@requireA18NProfile")
	public void createA18NProfileBeforeScenario(Scenario scenario) {
		if(Page.getA18NClient() == null) {
			Page.setA18NClient(new DefaultA18NClientBuilder().build());
		}
		if(Page.getA18NProfile() == null) {
			Page.setA18NProfile(Page.getA18NClient().createProfile());
		}
	}

	@After("@requireA18NProfile")
	public void removeA18NProfileAfterScenario(Scenario scenario) {
		if(Page.getA18NProfile() != null && Page.getA18NClient() != null) {
			Page.getA18NClient().deleteProfile(Page.getA18NProfile());
			Page.setA18NProfile(null);
		}
	}

	@Before(order = 1, value = "@requireExistingUser")
	public void createUserBeforeScenario() {
		Assert.assertNotNull(Page.getA18NProfile());

		User user = UserBuilder.instance()
                .setEmail(Page.getA18NProfile().getEmailAddress())
                .setFirstName("Mary E2E")
                .setLastName(Page.getA18NProfile().getProfileId())
                .setPassword("Abcd1234".toCharArray())
				.setMobilePhone(Page.getA18NProfile().getPhoneNumber())
                .setActive(true)
                .buildAndCreate(client);
		Assert.assertNotNull(user.getId());
		logger.info("User created: " + user.getProfile().getEmail());
		Page.setUser(user);
	}

	@Before("@requireEnrolledPhone")
	public void enrollSmsUserFactor() {
		Assert.assertNotNull(Page.getA18NProfile());
		Assert.assertNotNull(Page.getUser());

		SmsUserFactor smsUserFactor = client.instantiate(SmsUserFactor.class);
		smsUserFactor.getProfile().setPhoneNumber(Page.getA18NProfile().getPhoneNumber());
		Page.getUser().enrollFactor(smsUserFactor, false, null, null, true);
	}

	@After("@requireExistingUser")
	public void deleteUserAfterScenario() {
		if (Page.getUser() != null) {
			String userEmail = Page.getUser().getProfile().getEmail();
			Page.getUser().deactivate();
			Page.getUser().delete();
			Page.setUser(null);
			Page.setTotpSharedSecret(null);
			logger.info("User deleted: " + userEmail);
		} else {
			logger.warn("No user to delete");
		}
	}

	@Before("@requireMFAGroupsForUser")
	public void assignMFAGroupBeforeScenario(Scenario scenario) {
		Assert.assertNotNull(Page.getUser());
		List<String> groups = new ArrayList<>();
		groups.add("MFA Required");
		if (scenario.getId().contains("mfa_with_password_and_sms")) {
			groups.add("Phone Enrollment Required");
		}

		if (scenario.getId().contains("mfa_with_password_and_security_question")) {
			groups.add("Security Question Required");
		}

		List<Group> groupList = client.listGroups()
				.stream()
				.filter(group -> groups.contains(group.getProfile().getName()))
				.collect(Collectors.toList());
		Assert.assertFalse(groupList.isEmpty());
		groupList.forEach(group -> Page.getUser().addToGroup(group.getId()));
	}

	@Before("@requireWebAuthnRequiredGroupsForUser")
	public void assignWebAuthnRequiredBeforeScenario(Scenario scenario) {
		Assert.assertNotNull(Page.getUser());
		List<String> groups = new ArrayList<>();
		groups.add("WebAuthn Required");

		List<Group> groupList = client.listGroups()
				.stream()
				.filter(group -> groups.contains(group.getProfile().getName()))
				.collect(Collectors.toList());
		Assert.assertFalse(groupList.isEmpty());
		groupList.forEach(group -> Page.getUser().addToGroup(group.getId()));
	}

	@Before("@requirePasswordOptionalGroupForUser")
	public void assignPasswordOptionalGroupBeforeScenario(Scenario scenario) {
		Assert.assertNotNull(Page.getUser());
		List<String> groups = new ArrayList<>();
		groups.add("Password Optional");

		List<Group> groupList = client.listGroups()
				.stream()
				.filter(group -> groups.contains(group.getProfile().getName()))
				.collect(Collectors.toList());
		Assert.assertFalse(groupList.isEmpty());
		groupList.forEach(group -> Page.getUser().addToGroup(group.getId()));
	}

	@Before("@requireTOTPGroupForUser")
	public void assignTOTPGroupBeforeScenario() {
		Assert.assertNotNull(Page.getUser());
		List<Group> groupList = client.listGroups()
				.stream()
				.filter(group -> group.getProfile().getName().equals("TOTP Required"))
				.collect(Collectors.toList());
		Assert.assertFalse(groupList.isEmpty());
		groupList.forEach(group -> Page.getUser().addToGroup(group.getId()));
	}

	@Before("@requireEnrolledGoogleQR")
	public void enrollTotpUserFactor() {
		Assert.assertNotNull(Page.getA18NProfile());
		Assert.assertNotNull(Page.getUser());

		UserFactor totpUserFactor = client.instantiate(TokenUserFactor.class)
				.setFactorType(FactorType.TOKEN_SOFTWARE_TOTP)
				.setProvider(FactorProvider.GOOGLE);
		Page.getUser().enrollFactor(totpUserFactor);
		String secret = ((Map<String, String>) totpUserFactor.getEmbedded().get("activation")).get("sharedSecret");
		Page.setTotpSharedSecret(secret);

		ActivateFactorRequest activateFactorRequest = client.instantiate(ActivateFactorRequest.class);
		activateFactorRequest.setPassCode(QrCodePage.getOneTimePassword(secret));
		totpUserFactor.activate(activateFactorRequest);
	}

	@After("@requireUserDeletionAfterRegistration")
	public void deleteUserAfterRegistration() {
		if(Page.getA18NProfile() != null) {
			logger.info("Searching for a user to be deleted: " + Page.getA18NProfile().getEmailAddress());
		 	Optional<User> userToDelete = client.listUsers(Page.getA18NProfile().getEmailAddress(), null, null, null, null )
					.stream().filter(x -> x.getProfile().getEmail().equals(Page.getA18NProfile().getEmailAddress())).findFirst();
		 	if(userToDelete.isPresent()) {
				String userEmail = userToDelete.get().getProfile().getEmail();
		 		userToDelete.get().deactivate();
				userToDelete.get().delete();
				logger.info("User deleted: " + userEmail);
			} else {
				logger.warn("Fail to find a user to delete: " + Page.getA18NProfile().getEmailAddress());
			}
		}
	}

	@Before("@requireIDFirstPolicy")
	public void createIDFirstPolicy() {
		// Check if policy exists. Create one if not
		final String policyName = "ID First Policy";
		List<Policy> policyList = client.listPolicies(PolicyType.OKTA_SIGN_ON.toString())
				.stream()
				.filter(policy -> policy.getName().equals(policyName))
				.collect(Collectors.toList());

		if (policyList.size() > 0) {
			return;
		}

		OktaSignOnPolicy policy = (OktaSignOnPolicy) OktaSignOnPolicyBuilder.instance()
				.setName("ID First Policy")
				.setDescription("ID First Policy")
				.setType(PolicyType.OKTA_SIGN_ON)
				.setStatus(Policy.StatusEnum.ACTIVE)
				.buildAndCreate(client);

		OktaSignOnPolicyRule policyRule = (OktaSignOnPolicyRule) policy.createRule(client.instantiate(OktaSignOnPolicyRule.class)
				.setName("ID First Rule")
				.setActions(client.instantiate(OktaSignOnPolicyRuleActions.class)
						.setSignon(client.instantiate(OktaSignOnPolicyRuleSignonActions.class)
								.setAccess(OktaSignOnPolicyRuleSignonActions.AccessEnum.ALLOW)
								.setRequireFactor(false))));
	}

	@After("@requireIDFirstPolicyDeletionAfterTest")
	public void deleteIDFirstPolicy() {
		final String policyName = "ID First Policy";
		List<Policy> policyList = client.listPolicies(PolicyType.OKTA_SIGN_ON.toString())
				.stream()
				.filter(policy -> policy.getName().equals(policyName))
				.collect(Collectors.toList());

		if (policyList.size() == 0) {
			return;
		}

		for (Policy policy : policyList) {
			policy.deactivate();
			policy.delete();
		}

	}

	private boolean existsElement(String id) {
		try {
			driver.findElement(By.id(id));
		} catch (NoSuchElementException e) {
			return false;
		}
		return true;
	}

	/**
	 *
	 * @return true if driver is alive else false
	 */
	public Boolean isAlive() {
		try {
			driver.getCurrentUrl();//or driver.getTitle();
			return true;
		} catch (Exception ex) {
			return false;
		}
	}
}
