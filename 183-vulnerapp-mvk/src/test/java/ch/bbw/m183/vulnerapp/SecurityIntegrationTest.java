package ch.bbw.m183.vulnerapp;

import java.util.UUID;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseCookie;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class SecurityIntegrationTest {

	private static final String USER_PASSWORD = "BarbarossA123";
	private static final String ADMIN_PASSWORD = "Sup3rSecretAdmin";

	@Autowired
	WebTestClient web;

	WebTestClient anonymous;

	@BeforeEach
	void setUp() {
		anonymous = web.mutate().build();
	}

	enum Actor {
		ANONYMOUS,
		USER_WITHOUT_CSRF,
		USER_WITH_CSRF,
		ADMIN_WITH_CSRF
	}

	private record Auth(String sessionId, String csrfToken) {
	}

	static Stream<Arguments> accessRules() {
		return Stream.of(
				Arguments.of(HttpMethod.GET, "/", Actor.ANONYMOUS, 200),
				Arguments.of(HttpMethod.GET, "/", Actor.USER_WITHOUT_CSRF, 200),
				Arguments.of(HttpMethod.GET, "/", Actor.USER_WITH_CSRF, 200),
				Arguments.of(HttpMethod.GET, "/", Actor.ADMIN_WITH_CSRF, 200),

				Arguments.of(HttpMethod.GET, "/api/blog", Actor.ANONYMOUS, 200),
				Arguments.of(HttpMethod.GET, "/api/blog", Actor.USER_WITHOUT_CSRF, 200),
				Arguments.of(HttpMethod.GET, "/api/blog", Actor.USER_WITH_CSRF, 200),
				Arguments.of(HttpMethod.GET, "/api/blog", Actor.ADMIN_WITH_CSRF, 200),

				Arguments.of(HttpMethod.POST, "/api/blog", Actor.ANONYMOUS, 401),
				Arguments.of(HttpMethod.POST, "/api/blog", Actor.USER_WITHOUT_CSRF, 403),
				Arguments.of(HttpMethod.POST, "/api/blog", Actor.USER_WITH_CSRF, 201),
				Arguments.of(HttpMethod.POST, "/api/blog", Actor.ADMIN_WITH_CSRF, 201),

				Arguments.of(HttpMethod.GET, "/api/user/whoami", Actor.ANONYMOUS, 401),
				Arguments.of(HttpMethod.GET, "/api/user/whoami", Actor.USER_WITHOUT_CSRF, 200),
				Arguments.of(HttpMethod.GET, "/api/user/whoami", Actor.USER_WITH_CSRF, 200),
				Arguments.of(HttpMethod.GET, "/api/user/whoami", Actor.ADMIN_WITH_CSRF, 200),

				Arguments.of(HttpMethod.GET, "/api/admin/users", Actor.ANONYMOUS, 401),
				Arguments.of(HttpMethod.GET, "/api/admin/users", Actor.USER_WITHOUT_CSRF, 403),
				Arguments.of(HttpMethod.GET, "/api/admin/users", Actor.USER_WITH_CSRF, 403),
				Arguments.of(HttpMethod.GET, "/api/admin/users", Actor.ADMIN_WITH_CSRF, 200),

				Arguments.of(HttpMethod.GET, "/actuator/health", Actor.ANONYMOUS, 200),
				Arguments.of(HttpMethod.GET, "/actuator/health", Actor.USER_WITHOUT_CSRF, 200),
				Arguments.of(HttpMethod.GET, "/actuator/health", Actor.USER_WITH_CSRF, 200),
				Arguments.of(HttpMethod.GET, "/actuator/health", Actor.ADMIN_WITH_CSRF, 200)
		);
	}

	@ParameterizedTest(name = "{0} {1} as {2} -> {3}")
	@MethodSource("accessRules")
	@DisplayName("access control follows the assignment table")
	void accessControlMatchesAssignmentTable(HttpMethod method, String uri, Actor actor, int expectedStatus) {
		WebTestClient client = clientFor(actor);
		WebTestClient.RequestBodySpec request = client.method(method).uri(uri);

		if (method == HttpMethod.POST) {
			request.contentType(MediaType.APPLICATION_JSON)
					.bodyValue("{\"title\":\"security test\",\"body\":\"created by WebTestClient\"}");
		}

		request.exchange()
				.expectStatus().isEqualTo(expectedStatus);
	}

	@Test
	void healthEndpointHidesDetailsForAnonymousUsers() {
		anonymous.get().uri("/actuator/health")
				.exchange()
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.status").isEqualTo("UP")
				.jsonPath("$.components").doesNotExist();
	}

	@Test
	void healthEndpointShowsDetailsForAdminUsers() {
		clientFor(Actor.ADMIN_WITH_CSRF).get().uri("/actuator/health")
				.exchange()
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.status").isEqualTo("UP")
				.jsonPath("$.components").exists();
	}

	@Test
	void loginNeedsCsrfToken() {
		anonymous.post().uri("/login")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.bodyValue("username=fuu&password=" + USER_PASSWORD)
				.exchange()
				.expectStatus().value(status -> assertThat(status).isIn(401, 403));
	}

	@Test
	void logoutInvalidatesTheSession() {
		Auth user = loginAs("fuu", USER_PASSWORD);

		authedClient(user, true).post().uri("/logout")
				.exchange()
				.expectStatus().isNoContent();

		anonymous.get().uri("/api/user/whoami")
				.cookie("JSESSIONID", user.sessionId())
				.exchange()
				.expectStatus().isUnauthorized();
	}

	@Test
	void blogValidationRejectsEmptyAndOversizedInput() {
		WebTestClient user = clientFor(Actor.USER_WITH_CSRF);

		user.post().uri("/api/blog")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("{\"title\":\"\",\"body\":\"\"}")
				.exchange()
				.expectStatus().isBadRequest();

		user.post().uri("/api/blog")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("{\"title\":\"x\",\"body\":\"" + "a".repeat(10001) + "\"}")
				.exchange()
				.expectStatus().isBadRequest();
	}

	@Test
	void adminUserValidationRejectsWeakOrInvalidUsers() {
		WebTestClient admin = clientFor(Actor.ADMIN_WITH_CSRF);

		admin.post().uri("/api/admin/users")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("{\"username\":\"weak\",\"fullname\":\"Weak User\",\"password\":\"abc\",\"role\":\"USER\"}")
				.exchange()
				.expectStatus().isBadRequest();

		admin.post().uri("/api/admin/users")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("{\"username\":\"bad role\",\"fullname\":\"Bad Role\",\"password\":\"Strong1Pass\",\"role\":\"ROOT\"}")
				.exchange()
				.expectStatus().isBadRequest();
	}

	@Test
	void adminCanCreateAndDeleteUsersWithCsrf() {
		WebTestClient admin = clientFor(Actor.ADMIN_WITH_CSRF);
		String username = "u" + UUID.randomUUID().toString().replace("-", "").substring(0, 12);

		admin.post().uri("/api/admin/users")
				.contentType(MediaType.APPLICATION_JSON)
				.bodyValue("""
						{"username":"%s","fullname":"Temporary User","password":"Strong1Pass","role":"USER"}
						""".formatted(username))
				.exchange()
				.expectStatus().isCreated()
				.expectBody()
				.jsonPath("$.username").isEqualTo(username)
				.jsonPath("$.password").doesNotExist();

		admin.delete().uri("/api/admin/users/{username}", username)
				.exchange()
				.expectStatus().isNoContent();
	}

	@Test
	void userDataNeverLeaksPasswordHashesOrPlaintextPasswords() {
		clientFor(Actor.ADMIN_WITH_CSRF).get().uri("/api/admin/users")
				.exchange()
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.content[*].password").doesNotExist()
				.consumeWith(result -> {
					String body = new String(result.getResponseBody());
					assertThat(body).doesNotContain(USER_PASSWORD);
					assertThat(body).doesNotContain(ADMIN_PASSWORD);
					assertThat(body).doesNotContain("$2a$");
					assertThat(body).doesNotContain("$2b$");
					assertThat(body).doesNotContain("$2y$");
				});
	}

	@Test
	void maliciousUsernamePathVariableIsRejectedBeforeDatabaseAccess() {
		WebTestClient admin = clientFor(Actor.ADMIN_WITH_CSRF);

		admin.delete().uri("/api/admin/users/{username}", "'; DROP TABLE users;--")
				.exchange()
				.expectStatus().value(status -> assertThat(status).isBetween(400, 499));

		admin.get().uri("/api/admin/users")
				.exchange()
				.expectStatus().isOk()
				.expectBody()
				.jsonPath("$.content[?(@.username == 'admin')]").exists();
	}

	@Test
	void browserSecurityHeadersArePresent() {
		anonymous.get().uri("/")
				.exchange()
				.expectStatus().isOk()
				.expectHeader().exists("Content-Security-Policy")
				.expectHeader().exists("X-Content-Type-Options")
				.expectHeader().valueEquals("X-Frame-Options", "DENY");
	}

	@Test
	void frontendRendersBlogContentAsText() {
		anonymous.get().uri("/script.js")
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class)
				.consumeWith(result -> {
					String script = result.getResponseBody();
					assertThat(script).contains("textContent");
					assertThat(script).doesNotContain("innerHTML = blog");
				});
	}

	private WebTestClient clientFor(Actor actor) {
		return switch (actor) {
			case ANONYMOUS -> anonymous;
			case USER_WITHOUT_CSRF -> authedClient(loginAs("fuu", USER_PASSWORD), false);
			case USER_WITH_CSRF -> authedClient(loginAs("fuu", USER_PASSWORD), true);
			case ADMIN_WITH_CSRF -> authedClient(loginAs("admin", ADMIN_PASSWORD), true);
		};
	}

	private Auth loginAs(String username, String password) {
		String csrf = fetchCsrfToken(anonymous);

		EntityExchangeResult<byte[]> login = anonymous.post().uri("/login")
				.cookie("XSRF-TOKEN", csrf)
				.header("X-XSRF-TOKEN", csrf)
				.contentType(MediaType.APPLICATION_FORM_URLENCODED)
				.bodyValue("username=" + username + "&password=" + password)
				.exchange()
				.expectStatus().isOk()
				.expectBody().returnResult();

		String sessionId = login.getResponseCookies().getFirst("JSESSIONID").getValue();
		String freshCsrf = fetchCsrfToken(web.mutate()
				.defaultCookie("JSESSIONID", sessionId)
				.build());

		return new Auth(sessionId, freshCsrf);
	}

	private String fetchCsrfToken(WebTestClient client) {
		EntityExchangeResult<byte[]> result = client.get().uri("/api/blog")
				.exchange()
				.expectStatus().isOk()
				.expectBody().returnResult();

		ResponseCookie cookie = result.getResponseCookies().getFirst("XSRF-TOKEN");
		assertThat(cookie).as("GET /api/blog must return an XSRF-TOKEN cookie").isNotNull();
		return cookie.getValue();
	}

	private WebTestClient authedClient(Auth auth, boolean withCsrf) {
		WebTestClient.Builder builder = web.mutate()
				.defaultCookie("JSESSIONID", auth.sessionId());

		if (withCsrf) {
			builder.defaultCookie("XSRF-TOKEN", auth.csrfToken())
					.defaultHeader("X-XSRF-TOKEN", auth.csrfToken());
		}

		return builder.build();
	}
}
