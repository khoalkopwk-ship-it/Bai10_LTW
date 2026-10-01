package vn.iotstar;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.util.JSONObjectUtils;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.crypto.password.PasswordEncoder;
import vn.iotstar.repository.UserRepository;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class VdJwtApplicationTests {
    @Value("${local.server.port}")
    private int port;
    @Value("${security.jwt.secret-key}")
    private String secret;
    @Autowired
    private UserRepository users;
    @Autowired
    private PasswordEncoder passwordEncoder;
    private final HttpClient client = HttpClient.newHttpClient();

    private HttpResponse<String> request(String method, String path, String body, String token) throws Exception {
        var builder = HttpRequest.newBuilder(URI.create("http://localhost:" + port + path));
        if (token != null) builder.header("Authorization", "Bearer " + token);
        if (body != null) builder.header("Content-Type", "application/json");
        builder.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return client.send(builder.build(), HttpResponse.BodyHandlers.ofString());
    }

    private String signup() throws Exception {
        String email = UUID.randomUUID() + "@example.com";
        String body = JSONObjectUtils.toJSONString(Map.of(
                "email", email, "password", "Password123!", "fullName", "Demo User"));
        var response = request("POST", "/auth/signup", body, null);
        assertEquals(200, response.statusCode(), response.body());
        assertFalse(response.body().contains("password"));
        assertTrue(passwordEncoder.matches("Password123!", users.findByEmail(email).orElseThrow().getPassword()));
        return email;
    }

    private String signedToken(String subject, Date expiry, String key, JWSAlgorithm algorithm) throws Exception {
        var jwt = new SignedJWT(new JWSHeader(algorithm), new JWTClaimsSet.Builder()
                .subject(subject).expirationTime(expiry).build());
        jwt.sign(new MACSigner(key.getBytes(StandardCharsets.UTF_8)));
        return jwt.serialize();
    }

    @Test
    void contextLoads() {
    }

    @Test
    void signupLoginAndReadProtectedApis() throws Exception {
        String email = signup();
        var login = request("POST", "/auth/login", JSONObjectUtils.toJSONString(
                Map.of("email", email, "password", "Password123!")), null);
        assertEquals(200, login.statusCode(), login.body());
        var result = JSONObjectUtils.parse(login.body());
        assertEquals(3600000L, ((Number) result.get("expiresIn")).longValue());
        String token = (String) result.get("token");
        assertEquals(JWSAlgorithm.HS256, SignedJWT.parse(token).getHeader().getAlgorithm());
        var profile = request("GET", "/users/me", null, token);
        assertEquals(200, profile.statusCode(), profile.body());
        assertEquals(email, JSONObjectUtils.parse(profile.body()).get("email"));
        assertFalse(profile.body().contains("password"));
        var list = request("GET", "/users", null, token);
        assertEquals(200, list.statusCode());
        assertTrue(list.body().contains(email));
        assertFalse(list.body().contains("password"));
        assertTrue(profile.headers().allValues("set-cookie").isEmpty());
    }

    @Test
    void wrongCredentialsAndUnknownUserReturn401() throws Exception {
        String email = signup();
        for (String account : new String[]{email, "missing@example.com"}) {
            var response = request("POST", "/auth/login", JSONObjectUtils.toJSONString(
                    Map.of("email", account, "password", "wrong-password")), null);
            assertEquals(401, response.statusCode(), response.body());
        }
    }

    @Test
    void missingAndMalformedTokensReturn401() throws Exception {
        for (String token : new String[]{null, "", "not-a-token"}) {
            var response = request("GET", "/users/me", null, token);
            assertEquals(401, response.statusCode(), response.body());
        }
        assertEquals(401, request("GET", "/users", null, null).statusCode());
    }

    @Test
    void expiredTamperedAndWrongAlgorithmTokensReturn401() throws Exception {
        String email = signup();
        Date future = new Date(System.currentTimeMillis() + 60000);
        String[] tokens = {
                signedToken(email, new Date(System.currentTimeMillis() - 60000), secret, JWSAlgorithm.HS256),
                signedToken(email, future, "different-secret-key-with-more-than-32-bytes", JWSAlgorithm.HS256),
                signedToken(email, future, secret + secret, JWSAlgorithm.HS512),
                signedToken(email, null, secret, JWSAlgorithm.HS256)
        };
        for (String token : tokens) {
            var response = request("GET", "/users/me", null, token);
            assertEquals(401, response.statusCode(), response.body());
        }
    }

    @Test
    void tokenForDeletedUserReturns401() throws Exception {
        String email = signup();
        String token = signedToken(email, new Date(System.currentTimeMillis() + 60000), secret, JWSAlgorithm.HS256);
        users.delete(users.findByEmail(email).orElseThrow());
        var response = request("GET", "/users/me", null, token);
        assertEquals(401, response.statusCode(), response.body());
    }

    @Test
    void invalidSignupAndDuplicateEmailAreHandled() throws Exception {
        assertEquals(400, request("POST", "/auth/signup", "{}", null).statusCode());
        String email = signup();
        var duplicate = request("POST", "/auth/signup", JSONObjectUtils.toJSONString(Map.of(
                "email", email, "password", "Password123!", "fullName", "Other User")), null);
        assertEquals(409, duplicate.statusCode(), duplicate.body());
    }

    @Test
    void pagesAndAssetsArePublic() throws Exception {
        for (String path : new String[]{"/login", "/user/profile", "/js/mainjs.js", "/css/main.css", "/images/avatar.svg"}) {
            assertEquals(200, request("GET", path, null, null).statusCode(), path);
        }
        assertTrue(request("GET", "/login", null, null).body().contains("login-form"));
        assertTrue(request("GET", "/user/profile", null, null).body().contains("profile-page"));
    }

    @Test
    void corsAllowsConfiguredOriginAndRejectsOthers() throws Exception {
        for (String origin : new String[]{"http://localhost:8005", "https://untrusted.example"}) {
            var preflight = HttpRequest.newBuilder(URI.create("http://localhost:" + port + "/users/me"))
                    .method("OPTIONS", HttpRequest.BodyPublishers.noBody())
                    .header("Origin", origin).header("Access-Control-Request-Method", "GET")
                    .header("Access-Control-Request-Headers", "authorization").build();
            var response = client.send(preflight, HttpResponse.BodyHandlers.ofString());
            if (origin.equals("http://localhost:8005")) {
                assertEquals(200, response.statusCode());
                assertEquals(origin, response.headers().firstValue("access-control-allow-origin").orElse(""));
            } else {
                assertEquals(403, response.statusCode());
            }
        }
    }
}
