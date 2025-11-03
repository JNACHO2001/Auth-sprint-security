package auth.sistema.controller;

import auth.sistema.dto.LoginUserRequest;
import auth.sistema.dto.RegisterUserRequest;
import auth.sistema.service.UserService;
import org.springframework.http.HttpStatus;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("api/auth")
public class AuthController {
    
    private final UserService service;
    
    public AuthController(UserService service) {
        this.service = service;
    }
    
    @PostMapping("/register")
    ResponseEntity<?> crear(@RequestBody RegisterUserRequest req) {
        var res = service.registrar(req);
        return ResponseEntity.status(HttpStatus.CREATED).body(res);
        
    }
    
    @PostMapping("/login")
    
    ResponseEntity<?> login(@RequestBody LoginUserRequest req) {
        
        var res = service.login(req);
        
        return ResponseEntity.ok("Bienvenido " + res.getEmail()+res.getUsername()+res.getRole());
        
    }
    
}
