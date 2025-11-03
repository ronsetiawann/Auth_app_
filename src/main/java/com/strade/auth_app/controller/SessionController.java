package com.strade.auth_app.controller;

import com.strade.auth_app.dto.response.ApiResponse;
import com.strade.auth_app.dto.response.SessionResponse;
import com.strade.auth_app.security.SecurityContextUtil;
import com.strade.auth_app.service.SessionService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.UUID;

/**
 * Session Management REST API Controller
 */
@RestController
@RequestMapping("/api/v1/sessions")
@RequiredArgsConstructor
@Slf4j
@Tag(name = "Sessions", description = "Session Management APIs")
public class SessionController {

    private final SessionService sessionService;

    /**
     * Get current session
     * GET /api/v1/sessions/current
     */
    @GetMapping("/current")
    @Operation(summary = "Get current session", description = "Get current authenticated session details")
    public ResponseEntity<ApiResponse<SessionResponse>> getCurrentSession() {
        UUID sessionId = SecurityContextUtil.requireAuthentication().getSessionId();

        log.debug("Get current session: sessionId={}", sessionId);

        SessionResponse response = sessionService.getSessionDetails(sessionId);

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * Get session by ID
     * GET /api/v1/sessions/{sessionId}
     */
    @GetMapping("/{sessionId}")
    @Operation(summary = "Get session by ID", description = "Get session details by session ID")
    public ResponseEntity<ApiResponse<SessionResponse>> getSession(
            @PathVariable UUID sessionId
    ) {
        String userId = SecurityContextUtil.requireAuthentication().getUserId();

        log.debug("Get session: sessionId={}, requestedBy={}", sessionId, userId);

        SessionResponse response = sessionService.getSessionDetails(sessionId);

        // Security check: only allow user to view their own sessions
        if (!response.getUserId().equals(userId)) {
            return ResponseEntity.status(403).body(
                    ApiResponse.error(403, "Access denied")
            );
        }

        return ResponseEntity.ok(ApiResponse.success(response));
    }

    /**
     * List active sessions
     * GET /api/v1/sessions
     */
    @GetMapping
    @Operation(summary = "List active sessions", description = "List all active sessions for current user")
    public ResponseEntity<ApiResponse<List<SessionResponse>>> listSessions() {
        String userId = SecurityContextUtil.requireAuthentication().getUserId();

        log.debug("List sessions: userId={}", userId);

        List<SessionResponse> sessions = sessionService.listActiveSessions(userId);

        return ResponseEntity.ok(ApiResponse.success(sessions));
    }

    /**
     * Count active sessions
     * GET /api/v1/sessions/count
     */
    @GetMapping("/count")
    @Operation(summary = "Count active sessions", description = "Get count of active sessions")
    public ResponseEntity<ApiResponse<Long>> countSessions() {
        String userId = SecurityContextUtil.requireAuthentication().getUserId();

        log.debug("Count sessions: userId={}", userId);

        long count = sessionService.countActiveSessions(userId);

        return ResponseEntity.ok(ApiResponse.success(count));
    }
}
