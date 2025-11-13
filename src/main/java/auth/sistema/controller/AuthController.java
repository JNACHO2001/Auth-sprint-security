package auth.sistema.controller;


import auth.sistema.dto.*;
import auth.sistema.jwt.JwtService;
import auth.sistema.model.User;
import auth.sistema.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;
    private final JwtService jwtService;
    private final AuthenticationManager authManager;

    public AuthController(UserService userService, JwtService jwtService, AuthenticationManager authManager) {
        this.userService = userService;
        this.jwtService = jwtService;
        this.authManager = authManager;
    }

    // 🧾 Registro de usuario
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody RegisterUserRequest request) {
        User user = userService.register(request);
       
        return ResponseEntity.status(HttpStatus.CREATED)
                .body("Usuario creado");
    }

    // 🔑 Login de usuario
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginUserRequest request) {
        // Autentica las credenciales
        authManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()
                )
        );

        User user = userService.getByUsername(request.getUsername());
        String token = jwtService.generarToken(user);
        return ResponseEntity.ok(new AuthResponse(user.getUsername(), token));
    }
}
