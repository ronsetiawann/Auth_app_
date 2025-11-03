package com.strade.auth_app.service;

import com.strade.auth_app.constant.AppConstants;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Map;

/**
 * Service untuk mapping channel names
 */
@Slf4j
@Service
public class ChannelMappingService {

    private static final Map<String, String> LEGACY_TO_STANDARD = Map.of(
            AppConstants.CHANNEL_LEGACY_IDXMOBILE, AppConstants.CHANNEL_ANDROID,
            AppConstants.CHANNEL_LEGACY_MOBILE, AppConstants.CHANNEL_ANDROID,
            AppConstants.CHANNEL_LEGACY_WEB, AppConstants.CHANNEL_WEB
    );

    /**
     * Map legacy channel name to standard code
     *
     * @param channel Channel name (can be legacy)
     * @return Standard channel code
     */
    public String mapToStandardChannel(String channel) {
        if (channel == null) {
            return null;
        }

        String upper = channel.toUpperCase();
        String mapped = LEGACY_TO_STANDARD.getOrDefault(upper, upper);

        log.debug("Mapped channel {} to {}", channel, mapped);
        return mapped;
    }

    /**
     * Determine device type from channel and appCode
     *
     * @param channel Channel code
     * @param appCode Application code
     * @return Device type (mobile, tablet, desktop, web)
     */
    public String determineDeviceType(String channel, String appCode) {
        if (channel == null) {
            return "unknown";
        }

        return switch (channel.toUpperCase()) {
            case "AD", "OS", "AM" -> "mobile";
            case "OT" -> "tablet";
            case "RT" -> "desktop";
            case "WB" -> "web";
            case "BB" -> "blackberry";
            default -> "other";
        };
    }

    /**
     * Get user-friendly channel name
     */
    public String getChannelDisplayName(String channel) {
        if (channel == null) {
            return "Unknown";
        }

        return switch (channel.toUpperCase()) {
            case "AD" -> "Android";
            case "OS" -> "iOS";
            case "BB" -> "BlackBerry";
            case "WB" -> "Web Browser";
            case "OA" -> "Other App";
            case "AM" -> "Mobile App";
            case "OT" -> "Tablet";
            case "RT" -> "Desktop";
            default -> channel;
        };
    }
}
