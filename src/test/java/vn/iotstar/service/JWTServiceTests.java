package vn.iotstar.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.security.core.userdetails.User;
import vn.iotstar.exception.InvalidTokenException;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import static org.junit.jupiter.api.Assertions.*;

class JWTServiceTests {
    private static final String SECRET = "test-only-secret-key-at-least-32-bytes-long";

    @Test
    void rejectsShortKeyAndNonPositiveExpiration() {
        assertThrows(IllegalArgumentException.class, () -> new JWTService("YOUR_SECRET_KEY", 3600000));
        assertThrows(IllegalArgumentException.class, () -> new JWTService(SECRET, 0));
    }

    @Test
    void generatedKeyWorksAndDifferentServiceCannotVerifyIt() {
        var first = new JWTService("", 3600000);
        var second = new JWTService("", 3600000);
        var user = User.withUsername("demo@example.com").password("unused").authorities("USER").build();
        String token = first.generateToken(user);
        assertTrue(first.isTokenValid(token, user));
        assertFalse(second.isTokenValid(token, user));
        assertTrue(first.extractExpiration(token).after(new Date()));
        var other = User.withUsername("other@example.com").password("unused").authorities("USER").build();
        assertFalse(first.isTokenValid(token, other));
    }

    @Test
    void rejectsMissingSubjectAndFutureNotBefore() throws Exception {
        var service = new JWTService(SECRET, 3600000);
        for (var claims : new JWTClaimsSet[]{
                new JWTClaimsSet.Builder().expirationTime(new Date(System.currentTimeMillis() + 60000)).build(),
                new JWTClaimsSet.Builder().subject("demo@example.com")
                        .expirationTime(new Date(System.currentTimeMillis() + 120000))
                        .notBeforeTime(new Date(System.currentTimeMillis() + 60000)).build()}) {
            var jwt = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claims);
            jwt.sign(new MACSigner(SECRET.getBytes(StandardCharsets.UTF_8)));
            assertThrows(InvalidTokenException.class, () -> service.validateToken(jwt.serialize()));
        }
    }
}
