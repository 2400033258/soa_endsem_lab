
package com.example.jwtvalidation;

import java.util.Map;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;

@RestController
@RequestMapping("/api/jwt")
public class JwtController {

    private final JwtService jwtService;

    public JwtController(JwtService jwtService) {
        this.jwtService = jwtService;
    }

    // Generate Token
    @PostMapping("/generate")
    public ResponseEntity<?> generate(
            @RequestBody Map<String, String> request) {

        String username = request.get("username");

        if (username == null || username.isBlank()) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Username is required"));
        }

        String token = jwtService.generateToken(username);

        return ResponseEntity.ok(
                Map.of("token", token)
        );
    }

    // Validate Token
    @PostMapping("/validate")
    public ResponseEntity<?> validate(
            @RequestBody Map<String, String> request) {

        try {
            String token = request.get("token");

            if (token == null || token.isBlank()) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Token is required"));
            }

            Claims claims = jwtService.validateToken(token);

            return ResponseEntity.ok(
                Map.of(
                    "message", "Token Valid",
                    "username", claims.getSubject(),
                    "role", claims.get("role"),
                    "issuedAt", claims.getIssuedAt(),
                    "expiration", claims.getExpiration()
                )
            );

        } catch (ExpiredJwtException e) {

            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Token Expired"));

        } catch (JwtException | IllegalArgumentException e) {

            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Invalid or Tampered Token"));
        }
    }
}

