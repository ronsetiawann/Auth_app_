package com.strade.auth_app.service;

import com.strade.auth_app.entity.BridgingClientUser;
import com.strade.auth_app.entity.Client;
import com.strade.auth_app.exception.AuthException;
import com.strade.auth_app.exception.ErrorCode;
import com.strade.auth_app.repository.jpa.BridgingClientUserRepository;
import com.strade.auth_app.repository.jpa.ClientRepository;
import com.strade.auth_app.repository.jpa.OtpChallengeRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.Optional;
import java.util.UUID;

/**
 * User service - Get client info from SL.SClientView
 */
@Service
@Slf4j
@RequiredArgsConstructor
public class UserService {

    private final ClientRepository clientRepository;
    private final BridgingClientUserRepository bridgingClientUserRepository;
    private final OtpChallengeRepository otpChallengeRepository;

    /**
     * Get client ID from user ID using BridgingClientUser
     * Note: userId = dealerId in BridgingClientUser table
     */
    private String getClientIdFromUserId(String userId) {
        return bridgingClientUserRepository.findByDealerId(userId)
                .map(BridgingClientUser::getClientId)
                .orElse(userId); // Fallback to userId if not found
    }

    /**
     * Get client info
     */
    public Client getClient(String userId) {
        String clientId = getClientIdFromUserId(userId);

        return clientRepository.findByClientId(clientId)
                .orElseThrow(() -> new AuthException(
                        ErrorCode.USER_NOT_FOUND,
                        "Client not found: " + clientId
                ));
    }

    /**
     * Get display name from SL.SClientView
     */
    public String getUserDisplayName(String userId) {
        try {
            Client client = getClient(userId);
            return client.getDisplayName();
        } catch (Exception e) {
            log.warn("Failed to get client display name for {}, using userId", userId);
            return userId;
        }
    }

    public String getUserDisplayNameByClientId(String clientId) {
        try {
            return clientRepository.findByClientId(clientId)
                    .map(Client::getDisplayName)
                    .filter(name -> !name.isEmpty())
                    .orElseGet(() -> {
                        log.warn("Client or display name not found for clientId: {}, using clientId as display name", clientId);
                        return clientId;
                    });
        } catch (Exception e) {
            log.warn("Failed to get client display name for clientId: {}, using clientId as fallback. Error: {}",
                    clientId, e.getMessage());
            return clientId;
        }
    }


    /**
     * Get email from SL.SClientView
     */
    public String getUserEmail(String userId) {
        Client client = getClient(userId);

        if (client.getEmail() == null || client.getEmail().isEmpty()) {
            throw new AuthException(
                    ErrorCode.INVALID_REQUEST,
                    "Email not configured"
            );
        }

        return client.getEmail();
    }

    /**
     * Get phone from SL.SClientView (formatted)
     */
    public String getUserMobilePhone(String userId) {
        Client client = getClient(userId);
        if (client.getPhone() == null || client.getPhone().isEmpty()) {
            throw new AuthException(
                    ErrorCode.INVALID_REQUEST,
                    "Phone number not configured"
            );
        }
        return client.getFormattedPhone();
    }

    public String getUserMobilePhoneByClientId(String clientId) {
        return clientRepository.findByClientId(clientId)
                .map(client -> {
                    if (client.getPhone() == null || client.getPhone().isEmpty()) {
                        throw new AuthException(
                                ErrorCode.INVALID_REQUEST,
                                "Phone number not configured for clientId: " + clientId
                        );
                    }
                    return client.getFormattedPhone();
                })
                .orElseThrow(() -> new AuthException(
                        ErrorCode.INVALID_REQUEST,
                        "Client not found: " + clientId
                ));
    }

    /**
     * get userId by challenge id
     */
    public String getUserIdByChallengeId(String challengeId) {
        return otpChallengeRepository.findByChallengeId(UUID.fromString(challengeId))
                .orElseThrow(() -> new AuthException(
                        ErrorCode.OTP_INVALID,
                        "Invalid or expired OTP challenge: " + challengeId
                ))
                .getUserId();
    }

}