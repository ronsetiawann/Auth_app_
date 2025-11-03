package com.strade.auth_app.security.device;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Device fingerprint data
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class DeviceFingerprint {

    private String deviceId;          // SHA-256 hash of combined data
    private String deviceType;        // mobile, tablet, desktop, web
    private String deviceName;        // User-friendly name

    // Raw components
    private String userAgent;
    private String screenResolution;
    private String timezone;
    private String language;
    private String platform;
    private String channel;
    private String appCode;

    /**
     * Generate user-friendly device name
     */
    public String generateDeviceName() {
        if (deviceName != null && !deviceName.isEmpty()) {
            return deviceName;
        }

        // Try to extract from user agent
        if (userAgent != null) {
            // Extract browser/device info
            if (userAgent.contains("Chrome")) {
                return "Chrome Browser";
            } else if (userAgent.contains("Firefox")) {
                return "Firefox Browser";
            } else if (userAgent.contains("Safari")) {
                return "Safari Browser";
            } else if (userAgent.contains("Edge")) {
                return "Edge Browser";
            } else if (userAgent.contains("Android")) {
                return "Android Device";
            } else if (userAgent.contains("iPhone")) {
                return "iPhone";
            } else if (userAgent.contains("iPad")) {
                return "iPad";
            } else if (userAgent.contains("Windows")) {
                return "Windows PC";
            } else if (userAgent.contains("Mac")) {
                return "Mac";
            } else if (userAgent.contains("Linux")) {
                return "Linux PC";
            }
        }

        // Fallback to channel-based name
        if (channel != null) {
            return switch (channel.toUpperCase()) {
                case "AD" -> "Android Device";
                case "OS" -> "iOS Device";
                case "WB" -> "Web Browser";
                case "RT" -> "Desktop Application";
                case "OT" -> "Tablet";
                default -> "Unknown Device";
            };
        }

        return "Unknown Device";
    }
}
