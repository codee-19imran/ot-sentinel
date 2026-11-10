package com.ot.sentinel.controller;

import com.ot.sentinel.security.JwtUtil;
import com.ot.sentinel.service.LoginAttemptService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/**
 * Authentication endpoints for the secure local login.
 * Issues a JWT carried in an HttpOnly cookie on successful sign-in.
 */
@Controller
@RequestMapping("/api/auth")
public class AuthController {

    private static final String COOKIE_NAME = "OT_SENTINEL_TOKEN";

    private final AuthenticationManager authenticationManager;
    private final JwtUtil jwtUtil;
    private final LoginAttemptService loginAttemptService;

    public AuthController(AuthenticationManager authenticationManager,
                          JwtUtil jwtUtil,
                          LoginAttemptService loginAttemptService) {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.loginAttemptService = loginAttemptService;
    }

    @GetMapping("/")
    public String root() {
        return "redirect:/login";
    }

    @PostMapping("/login")
    public String doLogin(@RequestParam String username,
                          @RequestParam String password,
                          HttpServletRequest request,
                          HttpServletResponse response,
                          RedirectAttributes redirect) {
        String attemptKey = username.toLowerCase() + '|' + clientAddress(request);

        if (loginAttemptService.isLocked(attemptKey)) {
            long seconds = loginAttemptService.remainingLockSeconds(attemptKey);
            redirect.addFlashAttribute("error",
                    "Too many failed sign-in attempts. This account is locked for another "
                            + Math.max(1, seconds / 60) + " minute(s).");
            return "redirect:/login";
        }

        try {
            Authentication auth = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(username, password));
            loginAttemptService.recordSuccess(attemptKey);

            String token = jwtUtil.generateToken(auth.getName());
            addCookie(request, response, token);

            redirect.addFlashAttribute("success", "Welcome back, " + username + ".");
            return "redirect:/dashboard";
        } catch (Exception e) {
            loginAttemptService.recordFailure(attemptKey);
            redirect.addFlashAttribute("error", "Invalid username or password.");
            return "redirect:/login";
        }
    }

    @PostMapping("/logout")
    public String doLogout(HttpServletRequest request, HttpServletResponse response) {
        clearCookie(request, response);
        return "redirect:/login";
    }

    private void addCookie(HttpServletRequest req, HttpServletResponse res, String token) {
        Cookie cookie = new Cookie(COOKIE_NAME, token);
        cookie.setHttpOnly(true);
        cookie.setSecure(req.isSecure());   // true when served over HTTPS
        cookie.setPath("/");
        cookie.setMaxAge((int) (jwtUtil.getExpiration() / 1000));
        // SameSite=Lax keeps the session cookie out of cross-site POSTs (CSRF hardening)
        cookie.setAttribute("SameSite", "Lax");
        res.addCookie(cookie);
    }

    private void clearCookie(HttpServletRequest req, HttpServletResponse res) {
        Cookie cookie = new Cookie(COOKIE_NAME, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(req.isSecure());
        cookie.setPath("/");
        cookie.setMaxAge(0);
        cookie.setAttribute("SameSite", "Lax");
        res.addCookie(cookie);
    }

    /** Best-effort client address for per-client lockout bookkeeping. */
    private String clientAddress(HttpServletRequest request) {
        String forwarded = request.getHeader("X-Forwarded-For");
        if (forwarded != null && !forwarded.isBlank()) {
            return forwarded.split(",")[0].trim();
        }
        return request.getRemoteAddr() == null ? "unknown" : request.getRemoteAddr();
    }
}
