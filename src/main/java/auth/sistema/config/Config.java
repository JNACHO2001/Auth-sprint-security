package auth.sistema.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class Config {
    // aqui desabilitamos toda la seguridad de sprint para poder hacer peticiones sin permiso
    @Bean
    SecurityFilterChain  web(HttpSecurity http) throws Exception {
        http.cors(withDefaults())
                .csrf(csrf-> csrf.disable())
                .authorizeHttpRequests((authorize)   -> authorize
                        .requestMatchers("api/auth/login").permitAll()
                        .anyRequest().authenticated()
                
                
                
                )
                .sessionManagement((session)  -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                
                
                ) ;
        return http.build();
                
            
    
    }
    // aqui creamos la configuracion de las contraseñas encriptadas
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}