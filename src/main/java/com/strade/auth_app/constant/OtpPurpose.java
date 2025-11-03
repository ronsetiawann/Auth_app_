package com.strade.auth_app.constant;

/**
 * OTP purpose constants
 */
public final class OtpPurpose {

    private OtpPurpose() {
        throw new IllegalStateException("Utility class");
    }

    // Authentication purposes
    public static final String LOGIN_2FA = "login_2fa";
    public static final String TRUST_DEVICE = "trust_device";

    // Stock Trading Transaction purposes (NEW)
    public static final String TRANSACTION_BUY_STOCK = "TRANSACTION_BUY_STOCK";
    public static final String TRANSACTION_SELL_STOCK = "TRANSACTION_SELL_STOCK";
    public static final String TRANSACTION_WITHDRAWAL = "TRANSACTION_WITHDRAWAL";
    public static final String TRANSACTION_DEPOSIT = "TRANSACTION_DEPOSIT";
    public static final String TRANSACTION_FUND_TRANSFER = "TRANSACTION_FUND_TRANSFER";

    public static boolean isTransactionPurpose(String purpose) {
        return purpose != null && purpose.startsWith("TRANSACTION_");
    }
}