package vn.iotstar.service;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import vn.iotstar.exception.InvalidTokenException;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.text.ParseException;
import java.util.Date;

@Service
public class JWTService {
    private final byte[] secretKey;
    private final long jwtExpiration;

    public JWTService(@Value("${security.jwt.secret-key:}") String configuredKey,
                      @Value("${security.jwt.expiration-time}") long jwtExpiration) {
        if (configuredKey.isBlank()) {
            secretKey = new byte[32];
            new SecureRandom().nextBytes(secretKey);
        } else {
            secretKey = configuredKey.getBytes(StandardCharsets.UTF_8);
        }
        if (secretKey.length < 32) {
            throw new IllegalArgumentException("JWT_SECRET_KEY must contain at least 32 UTF-8 bytes");
        }
        if (jwtExpiration <= 0) {
            throw new IllegalArgumentException("JWT expiration must be positive");
        }
        this.jwtExpiration = jwtExpiration;
    }

    public String generateToken(UserDetails userDetails) {
        Date now = new Date();
        JWTClaimsSet claims = new JWTClaimsSet.Builder()
                .subject(userDetails.getUsername()).issueTime(now)
                .expirationTime(new Date(now.getTime() + jwtExpiration)).build();
        try {
            SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.HS256)
                    .type(JOSEObjectType.JWT).build(), claims);
            jwt.sign(new MACSigner(secretKey));
            return jwt.serialize();
        } catch (JOSEException e) {
            throw new IllegalStateException("Could not generate JWT", e);
        }
    }

    // Verify the signature before trusting claims or looking up the user.
    public JWTClaimsSet validateToken(String token) {
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            if (!JWSAlgorithm.HS256.equals(jwt.getHeader().getAlgorithm())
                    || !jwt.verify(new MACVerifier(secretKey))) {
                throw new InvalidTokenException("Chữ ký JWT không hợp lệ.");
            }
            JWTClaimsSet claims = jwt.getJWTClaimsSet();
            if (claims.getSubject() == null || claims.getSubject().isBlank()
                    || claims.getExpirationTime() == null) {
                throw new InvalidTokenException("JWT thiếu thông tin bắt buộc.");
            }
            Date now = new Date();
            if (!claims.getExpirationTime().after(now)) {
                throw new InvalidTokenException("JWT đã hết hạn.");
            }
            if (claims.getNotBeforeTime() != null && claims.getNotBeforeTime().after(now)) {
                throw new InvalidTokenException("JWT chưa có hiệu lực.");
            }
            return claims;
        } catch (ParseException | JOSEException e) {
            throw new InvalidTokenException("JWT không hợp lệ.", e);
        }
    }

    public String extractUsername(String token) { return validateToken(token).getSubject(); }
    public Date extractExpiration(String token) { return validateToken(token).getExpirationTime(); }
    public long getExpirationTime() { return jwtExpiration; }

    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            return extractUsername(token).equals(userDetails.getUsername());
        } catch (InvalidTokenException e) {
            return false;
        }
    }
}
