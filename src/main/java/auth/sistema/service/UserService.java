package auth.sistema.service;

import auth.sistema.dto.AuthResponse;
import auth.sistema.dto.LoginUserRequest;
import auth.sistema.dto.RegisterUserRequest;
import auth.sistema.model.Role;
import auth.sistema.model.User;
import auth.sistema.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final PasswordEncoder password;

    private final UserRepository user;

    public UserService(PasswordEncoder password, UserRepository user) {
        this.password = password;
        this.user = user;
    }

    public AuthResponse registrar(RegisterUserRequest req) {
        if (user.existsByEmail(req.getEmail())) {
            throw new RuntimeException("el correo ya esta registrado");

        }
        if (user.existsByUsername(req.getUsername())) {
              throw new RuntimeException("el usuario ya esta registrado");

            
            
        }

        var user = new User();
        user.setEmail(req.getEmail());
        user.setUsername(req.getUsername());
        user.setPassword(password.encode(req.getPassword()));
        user.setRole(Role.USER);
        var saved = this.user.save(user);

        return new AuthResponse(saved.getEmail(), saved.getUsername(), saved.getRole().name());

    }
    
    
    public AuthResponse login(LoginUserRequest req) {
      var user = this.user.findByUsername(req.getUsername()).orElseThrow(() -> new RuntimeException("no se encontro el usuario"));
      
        
        if (!password.matches(req.getPassword(),user.getPassword())) {
            
            throw  new RuntimeException("la contyraseña es incorrecta");
            
        }
        return  new AuthResponse(
                user.getEmail(),
                user.getUsername(),
                user.getRole().name()
        
        
        );
        
        
        
        

        
        
        
        
    
    
    }

}
