package com.ot.sentinel.controller;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import com.ot.sentinel.security.JwtUtil;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Authentication endpoints for the secure local login.
 * Issues a JWT carried in an HttpOnly cookie on successful sign-in.
 */
@Controller
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;

    public AuthController(AuthenticationManager authenticationManager, JwtUtil jwtUtil) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
    }

    @GetMapping("/login")
    public String loginPage(Model model) {
        return "login";
    }

    @GetMapping("/")
    public String root() {
        return "redirect:/login";
    }

    @PostMapping("/login")
    public String doLogin(@RequestParam String username,
                          @RequestParam String password,
                          HttpServletResponse response,
                          RedirectAttributes redirect) {
        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            SecurityContextHolder.getContext().setAuthentication(auth);

            String token = jwtUtil.generateToken(auth.getName());
            addCookie(response, token);

            redirect.addFlashAttribute("success", "Welcome back, " + username + ".");
            return "redirect:/dashboard";
        } catch (Exception e) {
            redirect.addFlashAttribute("error", "Invalid username or password.");
            return "redirect:/login";
        }
    }

    @PostMapping("/logout")
    public String doLogout(HttpServletResponse response) {
        clearCookie(response);
        return "redirect:/login";
    }

    private void addCookie(HttpServletResponse res, String token) {
        Cookie cookie = new Cookie("OT_SENTINEL_TOKEN", token);
        cookie.setHttpOnly(true);
        cookie.setSecure(false); // localhost / air-gapped LAN (no TLS)
        cookie.setPath("/");
        cookie.setMaxAge((int) (jwtUtil.getExpiration() / 1000));
        res.addCookie(cookie);
    }

    private void clearCookie(HttpServletResponse res) {
        Cookie cookie = new Cookie("OT_SENTINEL_TOKEN", null);
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        res.addCookie(cookie);
    }
}
