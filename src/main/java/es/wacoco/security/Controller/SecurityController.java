package es.wacoco.security.Controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class SecurityController {

    @GetMapping("/login")
    public String login() {
        return "login";
    }
    @GetMapping("/error")
    public String handleError() {
        // Logic to handle errors
        return "error";
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, Authentication authentication) {
        UserDetails userDetails = (UserDetails) authentication.getPrincipal();
        model.addAttribute("username", userDetails.getUsername());
        return "dashboard";
    }


    @PostMapping("/login")
    public String loginPost() {
        // Handle login logic if needed
        System.out.println("Login successful");
        return "redirect:/dashboard";
    }


    @PostMapping("/logout")
    public String logout() {
        // Perform logout logic if needed
        return "redirect:/login?logout";
    }

}
