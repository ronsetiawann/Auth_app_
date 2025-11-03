package com.strade.auth_app.security.device;

import com.strade.auth_app.util.HashUtil;
import jakarta.servlet.http.HttpServletRequest;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Extract device fingerprint from HTTP request
 */
@Slf4j
@Component
public class DeviceFingerprintExtractor {

    /**
     * Extract device fingerprint from request
     *
     * @param request HTTP request
     * @return Device fingerprint
     */
    public DeviceFingerprint extract(HttpServletRequest request) {
        // Extract components
        String userAgent = extractUserAgent(request);
        String screenResolution = extractScreenResolution(request);
        String timezone = extractTimezone(request);
        String language = extractLanguage(request);
        String platform = extractPlatform(request);

        // Generate device ID hash
        String deviceId = generateDeviceId(
                userAgent, screenResolution, timezone, language, platform
        );

        // Determine device type
        String deviceType = determineDeviceType(userAgent);

        DeviceFingerprint fingerprint = DeviceFingerprint.builder()
                .deviceId(deviceId)
                .deviceType(deviceType)
                .userAgent(userAgent)
                .screenResolution(screenResolution)
                .timezone(timezone)
                .language(language)
                .platform(platform)
                .build();

        // Generate user-friendly name
        fingerprint.setDeviceName(fingerprint.generateDeviceName());

        log.debug("Extracted device fingerprint: deviceId={}, type={}, name={}",
                deviceId, deviceType, fingerprint.getDeviceName());

        return fingerprint;
    }

    /**
     * Extract device fingerprint with custom channel and appCode
     */
    public DeviceFingerprint extract(
            HttpServletRequest request,
            String channel,
            String appCode
    ) {
        DeviceFingerprint fingerprint = extract(request);
        fingerprint.setChannel(channel);
        fingerprint.setAppCode(appCode);

        // Re-generate device ID with channel included
        String deviceId = generateDeviceId(
                fingerprint.getUserAgent(),
                fingerprint.getScreenResolution(),
                fingerprint.getTimezone(),
                fingerprint.getLanguage(),
                fingerprint.getPlatform(),
                channel
        );
        fingerprint.setDeviceId(deviceId);

        return fingerprint;
    }

    /**
     * Generate unique device ID hash
     */
    private String generateDeviceId(String... components) {
        List<String> parts = new ArrayList<>();

        for (String component : components) {
            if (component != null && !component.isEmpty()) {
                parts.add(component);
            }
        }

        String combined = String.join("|", parts);
        byte[] hash = HashUtil.sha256(combined);

        return HashUtil.toHex(hash);
    }

    /**
     * Extract User-Agent header
     */
    private String extractUserAgent(HttpServletRequest request) {
        String userAgent = request.getHeader("User-Agent");
        return userAgent != null ? userAgent : "Unknown";
    }

    /**
     * Extract screen resolution from custom header
     */
    private String extractScreenResolution(HttpServletRequest request) {
        // Custom header: X-Screen-Resolution (e.g., "1920x1080")
        String resolution = request.getHeader("X-Screen-Resolution");
        return resolution != null ? resolution : "unknown";
    }

    /**
     * Extract timezone from custom header
     */
    private String extractTimezone(HttpServletRequest request) {
        // Custom header: X-Timezone (e.g., "Asia/Jakarta" or "+0700")
        String timezone = request.getHeader("X-Timezone");
        return timezone != null ? timezone : "unknown";
    }

    /**
     * Extract language from Accept-Language header
     */
    private String extractLanguage(HttpServletRequest request) {
        String language = request.getHeader("Accept-Language");
        if (language != null && !language.isEmpty()) {
            // Extract first language (e.g., "en-US,en;q=0.9" -> "en-US")
            String[] parts = language.split(",");
            return parts[0].trim();
        }
        return "unknown";
    }

    /**
     * Extract platform from custom header or User-Agent
     */
    private String extractPlatform(HttpServletRequest request) {
        // Custom header: X-Platform (e.g., "Windows", "Android", "iOS")
        String platform = request.getHeader("X-Platform");

        if (platform == null || platform.isEmpty()) {
            // Try to detect from User-Agent
            String userAgent = extractUserAgent(request);
            platform = detectPlatformFromUserAgent(userAgent);
        }

        return platform;
    }

    /**
     * Detect platform from User-Agent string
     */
    private String detectPlatformFromUserAgent(String userAgent) {
        if (userAgent == null) {
            return "unknown";
        }

        String lower = userAgent.toLowerCase();

        if (lower.contains("windows")) {
            return "Windows";
        } else if (lower.contains("android")) {
            return "Android";
        } else if (lower.contains("iphone") || lower.contains("ipad")) {
            return "iOS";
        } else if (lower.contains("mac")) {
            return "macOS";
        } else if (lower.contains("linux")) {
            return "Linux";
        } else if (lower.contains("blackberry")) {
            return "BlackBerry";
        }

        return "unknown";
    }

    /**
     * Determine device type from User-Agent
     */
    private String determineDeviceType(String userAgent) {
        if (userAgent == null) {
            return "unknown";
        }

        String lower = userAgent.toLowerCase();

        // Mobile devices
        if (lower.contains("mobile") || lower.contains("android") ||
                lower.contains("iphone")) {
            return "mobile";
        }

        // Tablets
        if (lower.contains("tablet") || lower.contains("ipad")) {
            return "tablet";
        }

        // Desktop
        if (lower.contains("windows") || lower.contains("mac") ||
                lower.contains("linux")) {
            return "desktop";
        }

        // Default to web if accessed via browser
        if (lower.contains("chrome") || lower.contains("firefox") ||
                lower.contains("safari") || lower.contains("edge")) {
            return "web";
        }

        return "unknown";
    }
}
