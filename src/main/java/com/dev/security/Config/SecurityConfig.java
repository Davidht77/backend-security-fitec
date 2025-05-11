package com.dev.security.Config;

import com.nimbusds.jose.jwk.source.ImmutableSecret; // Importa ImmutableSecret
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder; // Importa NimbusReactiveJwtDecoder
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder; // Importa ReactiveJwtDecoder
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.web.reactive.function.client.WebClient;

import javax.crypto.SecretKey;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    @Value("${jwt.secret}")
    private String jwtSecretString;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    // Define el Bean para decodificar y validar JWTs usando la clave secreta
    @Bean
    public ReactiveJwtDecoder reactiveJwtDecoder() {
        SecretKey secretKey = getSigningKey();
        // Usa NimbusReactiveJwtDecoder configurado con la clave secreta
        // Esto valida la firma y la expiración automáticamente
        return NimbusReactiveJwtDecoder.withSecretKey(secretKey).build();
    }

    @Bean
    public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
                                                            ReactiveJwtDecoder reactiveJwtDecoder) { // Inyecta el decoder
        http
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .authorizeExchange(exchanges -> exchanges
                        .pathMatchers("/auth/register/**", "/auth/login", "/auth/admin/**").permitAll()
                        .pathMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs.yaml").permitAll()
                        .anyExchange().authenticated()
                )
                // Configura el Resource Server para usar el Bean ReactiveJwtDecoder que definiste
                .oauth2ResourceServer(oauth2 -> oauth2
                        .jwt(jwt -> jwt.jwtDecoder(reactiveJwtDecoder)) // <--- Usa el bean inyectado
                );
        // Alternativamente, si solo tienes UN bean ReactiveJwtDecoder,
        // a menudo Spring lo detecta automáticamente y podrías simplificar a:
        // .oauth2ResourceServer(ServerHttpSecurity.OAuth2ResourceServerSpec::jwt);

        return http.build();
    }

    // El método getSigningKey sigue siendo el mismo
    private SecretKey getSigningKey() {
        byte[] keyBytes;
        try {
            keyBytes = Decoders.BASE64.decode(this.jwtSecretString);
        } catch (IllegalArgumentException e) {
            keyBytes = this.jwtSecretString.getBytes(java.nio.charset.StandardCharsets.UTF_8);
        }
        return Keys.hmacShaKeyFor(keyBytes);
    }

    @Bean
    public WebClient.Builder webClientBuilder() {
        // Puedes añadir configuraciones por defecto aquí (timeouts, headers, etc.)
        return WebClient.builder();
    }
}
