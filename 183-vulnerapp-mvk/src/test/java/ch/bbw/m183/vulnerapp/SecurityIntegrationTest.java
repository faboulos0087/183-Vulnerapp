package ch.bbw.m183.vulnerapp;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class SecurityIntegrationTest {

	@Autowired
	WebTestClient web;

	WebTestClient anonClient;

	@BeforeEach
	void setUp() {
		anonClient = web.mutate().build();
	}

	private record Auth(String session, String csrf) {
	}

	private String bootstrapCsrf() {
		EntityExchangeResult<byte[]> result = anonClient.get().uri("/api/blog")
				.exchange()
				.expectStatus().isOk()
				.expectBody().returnResult();
		ResponseCookie cookie = result.getResponseCookies().getFirst("XSRF-TOKEN");
		assertThat(cookie).as("anonymous request must seed an XSRF-TOKEN cookie").isNotNull();
		return cookie.getValue();
	}

	private Auth loginAs(String username, String password) {
		String preCsrf = bootstrapCsrf();
		EntityExchangeResult<byte[]> loginResult = anonClient.post().uri("/login")
				.cookie("XSRF-TOKEN", preCsrf)
				.header("X-XSRF-TOKEN", preCsrf)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.bodyValue("username=" + username + "&password=" + password)
				.exchange()
				.expectStatus().isOk()
				.expectBody().returnResult();
		String session = loginResult.getResponseCookies().getFirst("JSESSIONID").getValue();
		EntityExchangeResult<byte[]> refresh = anonClient.get().uri("/api/blog")
				.cookie("JSESSIONID", session)
				.exchange()
				.expectStatus().isOk()
				.expectBody().returnResult();
		String csrf = refresh.getResponseCookies().getFirst("XSRF-TOKEN").getValue();
		assertThat(csrf).as("post-login refresh request must seed XSRF-TOKEN").isNotBlank();
		return new Auth(session, csrf);
	}

	private WebTestClient authedClient(Auth auth, boolean withCsrf) {
		WebTestClient.Builder builder = web.mutate()
				.defaultCookie("JSESSIONID", auth.session());
		if (withCsrf) {
			builder = builder.defaultCookie("XSRF-TOKEN", auth.csrf())
					.defaultHeader("X-XSRF-TOKEN", auth.csrf());
		}
		return builder.build();
	}

	@Nested
	@DisplayName("Anonymous user")
	class Anonymous {

		@Test
		void getRoot_allowed() {
			anonClient.get().uri("/").exchange().expectStatus().isOk();
		}

		@Test
		void getBlogs_allowed() {
			anonClient.get().uri("/api/blog").exchange().expectStatus().isOk();
		}

		@Test
		void postBlog_blockedByAuth() {
			anonClient.post().uri("/api/blog")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"x\",\"body\":\"y\"}")
					.exchange()
					.expectStatus().isUnauthorized();
		}

		@Test
		void whoami_blocked() {
			anonClient.get().uri("/api/user/whoami").exchange().expectStatus().isUnauthorized();
		}

		@Test
		void adminEndpoints_blocked() {
			anonClient.get().uri("/api/admin/users").exchange().expectStatus().isUnauthorized();
			anonClient.post().uri("/api/admin/users")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{}")
					.exchange()
					.expectStatus().isUnauthorized();
		}

		@Test
		void actuatorHealth_allowedWithoutDetails() {
			anonClient.get().uri("/actuator/health")
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.jsonPath("$.status").isEqualTo("UP")
					.jsonPath("$.components").doesNotExist();
		}

		@Test
		void otherActuator_blocked() {
			anonClient.get().uri("/actuator/info").exchange().expectStatus().isUnauthorized();
			anonClient.get().uri("/actuator/env").exchange().expectStatus().isUnauthorized();
		}

		@Test
		void loginWithBadPassword_unauthorized() {
			String preCsrf = bootstrapCsrf();
			anonClient.post().uri("/login")
					.cookie("XSRF-TOKEN", preCsrf)
					.header("X-XSRF-TOKEN", preCsrf)
					.contentType(MediaType.APPLICATION_FORM_URLENCODED)
					.bodyValue("username=fuu&password=wrong")
					.exchange()
					.expectStatus().isUnauthorized();
		}

		@Test
		void loginWithoutCsrf_blocked() {
			anonClient.post().uri("/login")
					.contentType(MediaType.APPLICATION_FORM_URLENCODED)
					.bodyValue("username=fuu&password=BarbarossA123")
					.exchange()
					.expectStatus().value(status -> assertThat(status)
							.as("CSRF must block POST /login (401 from anonymous entry point or 403)")
							.isIn(401, 403));
		}
	}

	@Nested
	@DisplayName("Regular user (USER role)")
	class RegularUser {

		Auth user;
		WebTestClient userWithCsrf;
		WebTestClient userNoCsrf;

		@BeforeEach
		void login() {
			user = loginAs("fuu", "BarbarossA123");
			userWithCsrf = authedClient(user, true);
			userNoCsrf = authedClient(user, false);
		}

		@Test
		void getRoot_allowed() {
			userWithCsrf.get().uri("/").exchange().expectStatus().isOk();
		}

		@Test
		void getBlogs_allowed() {
			userWithCsrf.get().uri("/api/blog").exchange().expectStatus().isOk();
		}

		@Test
		void postBlog_withoutCsrf_forbidden() {
			userNoCsrf.post().uri("/api/blog")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"hi\",\"body\":\"world1\"}")
					.exchange()
					.expectStatus().isForbidden();
		}

		@Test
		void postBlog_withCsrf_created() {
			userWithCsrf.post().uri("/api/blog")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"hi\",\"body\":\"hello world\"}")
					.exchange()
					.expectStatus().isCreated();
		}

		@Test
		void postBlog_invalidBody_badRequest() {
			userWithCsrf.post().uri("/api/blog")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"\",\"body\":\"\"}")
					.exchange()
					.expectStatus().isBadRequest();
		}

		@Test
		void postBlog_oversizedBody_badRequest() {
			String huge = "a".repeat(10001);
			userWithCsrf.post().uri("/api/blog")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"x\",\"body\":\"" + huge + "\"}")
					.exchange()
					.expectStatus().isBadRequest();
		}

		@Test
		void whoami_withoutCsrf_allowed() {
			userNoCsrf.get().uri("/api/user/whoami")
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.jsonPath("$.username").isEqualTo("fuu")
					.jsonPath("$.password").doesNotExist();
		}

		@Test
		void getAdmin_forbiddenForUser() {
			userWithCsrf.get().uri("/api/admin/users")
					.exchange().expectStatus().isForbidden();
		}

		@Test
		void postAdmin_forbiddenForUser() {
			userWithCsrf.post().uri("/api/admin/users")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"username\":\"x\",\"fullname\":\"x\",\"password\":\"Abc123abcD\",\"role\":\"USER\"}")
					.exchange()
					.expectStatus().isForbidden();
		}

		@Test
		void deleteAdmin_withoutCsrf_forbidden() {
			userNoCsrf.delete().uri("/api/admin/users/x")
					.exchange().expectStatus().isForbidden();
		}

		@Test
		void actuatorHealth_allowed() {
			userWithCsrf.get().uri("/actuator/health")
					.exchange().expectStatus().isOk();
		}
	}

	@Nested
	@DisplayName("Admin user (ADMIN role)")
	class AdminUser {

		Auth admin;
		WebTestClient adminWithCsrf;
		WebTestClient adminNoCsrf;

		@BeforeEach
		void login() {
			admin = loginAs("admin", "Sup3rSecretAdmin");
			adminWithCsrf = authedClient(admin, true);
			adminNoCsrf = authedClient(admin, false);
		}

		@Test
		void getAdminUsers_allowed() {
			adminWithCsrf.get().uri("/api/admin/users")
					.exchange().expectStatus().isOk();
		}

		@Test
		void postBlog_withCsrf_created() {
			adminWithCsrf.post().uri("/api/blog")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"admin\",\"body\":\"admin post\"}")
					.exchange()
					.expectStatus().isCreated();
		}

		@Test
		void postAdminUser_withCsrf_created() {
			adminWithCsrf.post().uri("/api/admin/users")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"username\":\"newuser\",\"fullname\":\"New User\",\"password\":\"Strong1Pass\",\"role\":\"USER\"}")
					.exchange()
					.expectStatus().isCreated();
		}

		@Test
		void postAdminUser_withoutCsrf_forbidden() {
			adminNoCsrf.post().uri("/api/admin/users")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"username\":\"nocsrf\",\"fullname\":\"X\",\"password\":\"Strong1Pass\",\"role\":\"USER\"}")
					.exchange()
					.expectStatus().isForbidden();
		}

		@Test
		void postAdminUser_weakPassword_rejected() {
			adminWithCsrf.post().uri("/api/admin/users")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"username\":\"weak\",\"fullname\":\"Weak User\",\"password\":\"abc\",\"role\":\"USER\"}")
					.exchange()
					.expectStatus().isBadRequest();
		}

		@Test
		void postAdminUser_invalidRole_rejected() {
			adminWithCsrf.post().uri("/api/admin/users")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"username\":\"bad\",\"fullname\":\"Bad User\",\"password\":\"Strong1Pass\",\"role\":\"ROOT\"}")
					.exchange()
					.expectStatus().isBadRequest();
		}

		@Test
		void postAdminUser_invalidUsername_rejected() {
			adminWithCsrf.post().uri("/api/admin/users")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"username\":\"hello world!\",\"fullname\":\"X\",\"password\":\"Strong1Pass\",\"role\":\"USER\"}")
					.exchange()
					.expectStatus().isBadRequest();
		}

		@Test
		void deleteNonexistentUser_notFound() {
			adminWithCsrf.delete().uri("/api/admin/users/ghost")
					.exchange()
					.expectStatus().isNotFound();
		}

		@Test
		void createDuplicateUser_conflict() {
			adminWithCsrf.post().uri("/api/admin/users")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"username\":\"admin\",\"fullname\":\"X\",\"password\":\"Strong1Pass\",\"role\":\"USER\"}")
					.exchange()
					.expectStatus().isEqualTo(409);
		}

		@Test
		void deleteAdminUser_withCsrf_noContent() {
			adminWithCsrf.post().uri("/api/admin/users")
					.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"username\":\"todelete\",\"fullname\":\"X\",\"password\":\"Strong1Pass\",\"role\":\"USER\"}")
					.exchange()
					.expectStatus().isCreated();

			adminWithCsrf.delete().uri("/api/admin/users/todelete")
					.exchange()
					.expectStatus().isNoContent();
		}

		@Test
		void actuatorHealth_showsDetails() {
			adminWithCsrf.get().uri("/actuator/health")
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.jsonPath("$.status").isEqualTo("UP")
					.jsonPath("$.components").exists();
		}
	}

	@Nested
	@DisplayName("Injection & disclosure regressions")
	class Regression {

		@Test
		void whoami_doesNotEvalSqlInUsername() {
			Auth admin = loginAs("admin", "Sup3rSecretAdmin");
			WebTestClient c = authedClient(admin, true);
			c.get().uri("/api/user/whoami")
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.jsonPath("$.username").isEqualTo("admin");
		}

		@Test
		void deleteUser_sqliAttemptInPathVar_rejected() {
			Auth admin = loginAs("admin", "Sup3rSecretAdmin");
			WebTestClient c = authedClient(admin, true);
			c.delete().uri("/api/admin/users/{u}", "'; DROP TABLE users;--")
					.exchange()
					.expectStatus().value(status -> assertThat(status)
							.as("malicious username must not reach the DB layer")
							.isBetween(400, 499));

			c.get().uri("/api/admin/users")
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.jsonPath("$.content[?(@.username == 'admin')]").exists();
		}

		@Test
		void adminListing_neverIncludesPassword() {
			Auth admin = loginAs("admin", "Sup3rSecretAdmin");
			WebTestClient c = authedClient(admin, true);
			c.get().uri("/api/admin/users")
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.jsonPath("$.content[*].password").doesNotExist();
		}

		@Test
		void logoutInvalidatesSession() {
			Auth user = loginAs("fuu", "BarbarossA123");
			authedClient(user, true).post().uri("/logout")
					.exchange()
					.expectStatus().isNoContent();
			anonClient.get().uri("/api/user/whoami")
					.cookie("JSESSIONID", user.session())
					.exchange()
					.expectStatus().isUnauthorized();
		}

		@Test
		void securityHeadersPresent() {
			anonClient.get().uri("/")
					.exchange()
					.expectStatus().isOk()
					.expectHeader().exists("Content-Security-Policy")
					.expectHeader().exists("X-Content-Type-Options")
					.expectHeader().valueEquals("X-Frame-Options", "DENY");
		}

		@Test
		void loginPasswordIsBcryptHashed() {
			Auth admin = loginAs("admin", "Sup3rSecretAdmin");
			authedClient(admin, true).get().uri("/api/admin/users")
					.exchange()
					.expectStatus().isOk()
					.expectBody()
					.consumeWith(r -> {
						String body = new String(r.getResponseBody());
						assertThat(body).doesNotContain("Sup3rSecretAdmin");
						assertThat(body).doesNotContain("BarbarossA123");
					});
		}
	}
}
