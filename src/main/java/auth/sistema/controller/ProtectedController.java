package auth.sistema.controller;

import java.util.Map;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/protected")
public class ProtectedController {

    // 🔒 Ruta protegida - Requiere estar autenticado
    @GetMapping("/hello")
    public ResponseEntity<?> hello(Authentication authentication) {
        return ResponseEntity.ok("¡Hola " + authentication.getName() + "! Tienes acceso.");
    }

    // 🔒 Ruta protegida - Muestra info del usuario
    @GetMapping("/me")
    public ResponseEntity<?> getUserInfo(Authentication authentication) {
        return ResponseEntity.ok(Map.of(
            "username", authentication.getName(),
            "authorities", authentication.getAuthorities(),
            "authenticated", authentication.isAuthenticated()
        ));
    }

    // 🔒 Solo para usuarios con rol USER
    @GetMapping("/user-only")
    @PreAuthorize("hasRole('USER')")
    public ResponseEntity<?> userOnly() {
        return ResponseEntity.ok("Endpoint solo para usuarios con rol USER");
    }

    // 🔒 Solo para usuarios con rol ADMIN
    @GetMapping("/admin-only")
    @PreAuthorize("hasRole('ADMIN')")
    public ResponseEntity<?> adminOnly() {
        return ResponseEntity.ok("Endpoint solo para ADMINISTRADORES");
    }

    // 🔒 Para USER o ADMIN
    @GetMapping("/user-or-admin")
    @PreAuthorize("hasAnyRole('USER', 'ADMIN')")
    public ResponseEntity<?> userOrAdmin(Authentication authentication) {
        return ResponseEntity.ok("Tienes acceso: " + authentication.getAuthorities());
    }
}