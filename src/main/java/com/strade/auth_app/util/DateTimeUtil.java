package com.strade.auth_app.util;

import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.time.temporal.ChronoUnit;

/**
 * Utility class for date/time operations
 * Works with LocalDateTime (matches SQL Server DATETIME2)
 */
public final class DateTimeUtil {

    private static final DateTimeFormatter ISO_FORMATTER = DateTimeFormatter.ISO_LOCAL_DATE_TIME;
    private static final DateTimeFormatter DISPLAY_FORMATTER =
            DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private DateTimeUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Get current UTC LocalDateTime
     *
     * @return Current LocalDateTime in UTC
     */
    public static LocalDateTime now() {
        return LocalDateTime.now(ZoneOffset.UTC);
    }

    /**
     * Add seconds to LocalDateTime
     *
     * @param dateTime Base LocalDateTime
     * @param seconds Seconds to add
     * @return New LocalDateTime
     */
    public static LocalDateTime plusSeconds(LocalDateTime dateTime, long seconds) {
        return dateTime.plusSeconds(seconds);
    }

    /**
     * Add minutes to LocalDateTime
     *
     * @param dateTime Base LocalDateTime
     * @param minutes Minutes to add
     * @return New LocalDateTime
     */
    public static LocalDateTime plusMinutes(LocalDateTime dateTime, long minutes) {
        return dateTime.plusMinutes(minutes);
    }

    /**
     * Add hours to LocalDateTime
     *
     * @param dateTime Base LocalDateTime
     * @param hours Hours to add
     * @return New LocalDateTime
     */
    public static LocalDateTime plusHours(LocalDateTime dateTime, long hours) {
        return dateTime.plusHours(hours);
    }

    /**
     * Add days to LocalDateTime
     *
     * @param dateTime Base LocalDateTime
     * @param days Days to add
     * @return New LocalDateTime
     */
    public static LocalDateTime plusDays(LocalDateTime dateTime, long days) {
        return dateTime.plusDays(days);
    }

    /**
     * Subtract minutes from LocalDateTime
     *
     * @param dateTime Base LocalDateTime
     * @param minutes Minutes to subtract
     * @return New LocalDateTime
     */
    public static LocalDateTime minusMinutes(LocalDateTime dateTime, long minutes) {
        return dateTime.minusMinutes(minutes);
    }

    /**
     * Subtract days from LocalDateTime
     *
     * @param dateTime Base LocalDateTime
     * @param days Days to subtract
     * @return New LocalDateTime
     */
    public static LocalDateTime minusDays(LocalDateTime dateTime, long days) {
        return dateTime.minusDays(days);
    }

    /**
     * Check if LocalDateTime is in the past
     *
     * @param dateTime LocalDateTime to check
     * @return true if past, false otherwise
     */
    public static boolean isPast(LocalDateTime dateTime) {
        return dateTime.isBefore(now());
    }

    /**
     * Check if LocalDateTime is in the future
     *
     * @param dateTime LocalDateTime to check
     * @return true if future, false otherwise
     */
    public static boolean isFuture(LocalDateTime dateTime) {
        return dateTime.isAfter(now());
    }

    /**
     * Format LocalDateTime to ISO string
     *
     * @param dateTime LocalDateTime to format
     * @return ISO formatted string (e.g., "2025-01-14T10:30:00")
     */
    public static String formatIso(LocalDateTime dateTime) {
        return ISO_FORMATTER.format(dateTime);
    }

    /**
     * Format LocalDateTime to display string
     * Format: yyyy-MM-dd HH:mm:ss
     *
     * @param dateTime LocalDateTime to format
     * @return Formatted string (e.g., "2025-01-14 10:30:00")
     */
    public static String formatDisplay(LocalDateTime dateTime) {
        return DISPLAY_FORMATTER.format(dateTime);
    }

    /**
     * Parse ISO string to LocalDateTime
     *
     * @param isoString ISO formatted string
     * @return LocalDateTime
     */
    public static LocalDateTime parseIso(String isoString) {
        return LocalDateTime.parse(isoString, ISO_FORMATTER);
    }

    /**
     * Parse display string to LocalDateTime
     *
     * @param displayString Display formatted string (yyyy-MM-dd HH:mm:ss)
     * @return LocalDateTime
     */
    public static LocalDateTime parseDisplay(String displayString) {
        return LocalDateTime.parse(displayString, DISPLAY_FORMATTER);
    }

    /**
     * Get seconds until target LocalDateTime
     *
     * @param targetDateTime Target LocalDateTime
     * @return Seconds until target (negative if past)
     */
    public static long secondsUntil(LocalDateTime targetDateTime) {
        return ChronoUnit.SECONDS.between(now(), targetDateTime);
    }

    /**
     * Get minutes until target LocalDateTime
     *
     * @param targetDateTime Target LocalDateTime
     * @return Minutes until target (negative if past)
     */
    public static long minutesUntil(LocalDateTime targetDateTime) {
        return ChronoUnit.MINUTES.between(now(), targetDateTime);
    }

    /**
     * Get seconds between two LocalDateTime
     *
     * @param start Start LocalDateTime
     * @param end End LocalDateTime
     * @return Seconds between (negative if end is before start)
     */
    public static long secondsBetween(LocalDateTime start, LocalDateTime end) {
        return ChronoUnit.SECONDS.between(start, end);
    }

    /**
     * Calculate TOTP time step
     * Used for TOTP code generation
     *
     * @param periodSeconds Period in seconds (default 30)
     * @return Current time step
     */
    public static long getTotpTimeStep(int periodSeconds) {
        // Convert LocalDateTime to epoch seconds (UTC)
        Instant instant = now().toInstant(ZoneOffset.UTC);
        return instant.getEpochSecond() / periodSeconds;
    }

    /**
     * Convert LocalDateTime to SQL Timestamp
     *
     * @param dateTime LocalDateTime
     * @return SQL Timestamp
     */
    public static java.sql.Timestamp toSqlTimestamp(LocalDateTime dateTime) {
        return java.sql.Timestamp.valueOf(dateTime);
    }

    /**
     * Convert SQL Timestamp to LocalDateTime
     *
     * @param timestamp SQL Timestamp
     * @return LocalDateTime
     */
    public static LocalDateTime fromSqlTimestamp(java.sql.Timestamp timestamp) {
        return timestamp.toLocalDateTime();
    }

    /**
     * Convert LocalDateTime to Instant (UTC)
     *
     * @param dateTime LocalDateTime
     * @return Instant
     */
    public static Instant toInstant(LocalDateTime dateTime) {
        return dateTime.toInstant(ZoneOffset.UTC);
    }

    /**
     * Convert Instant to LocalDateTime (UTC)
     *
     * @param instant Instant
     * @return LocalDateTime in UTC
     */
    public static LocalDateTime fromInstant(Instant instant) {
        return LocalDateTime.ofInstant(instant, ZoneOffset.UTC);
    }

    /**
     * Check if dateTime is between start and end (inclusive)
     *
     * @param dateTime DateTime to check
     * @param start Start datetime
     * @param end End datetime
     * @return true if between, false otherwise
     */
    public static boolean isBetween(LocalDateTime dateTime, LocalDateTime start, LocalDateTime end) {
        return !dateTime.isBefore(start) && !dateTime.isAfter(end);
    }

    /**
     * Get current date at start of day (00:00:00)
     *
     * @return LocalDateTime at start of today
     */
    public static LocalDateTime startOfToday() {
        return now().toLocalDate().atStartOfDay();
    }

    /**
     * Get current date at end of day (23:59:59)
     *
     * @return LocalDateTime at end of today
     */
    public static LocalDateTime endOfToday() {
        return now().toLocalDate().atTime(23, 59, 59);
    }

    /**
     * Truncate to seconds (remove milliseconds/nanoseconds)
     *
     * @param dateTime LocalDateTime
     * @return LocalDateTime truncated to seconds
     */
    public static LocalDateTime truncateToSeconds(LocalDateTime dateTime) {
        return dateTime.truncatedTo(ChronoUnit.SECONDS);
    }

    /**
     * Truncate to minutes (remove seconds/milliseconds/nanoseconds)
     *
     * @param dateTime LocalDateTime
     * @return LocalDateTime truncated to minutes
     */
    public static LocalDateTime truncateToMinutes(LocalDateTime dateTime) {
        return dateTime.truncatedTo(ChronoUnit.MINUTES);
    }

    // Add to DateTimeUtil.java

    /**
     * Convert LocalDateTime to Date (for JWT claims)
     *
     * @param dateTime LocalDateTime
     * @return java.util.Date
     */
    public static java.util.Date toDate(LocalDateTime dateTime) {
        return java.util.Date.from(dateTime.toInstant(ZoneOffset.UTC));
    }

    /**
     * Convert Date to LocalDateTime (from JWT claims)
     *
     * @param date java.util.Date
     * @return LocalDateTime in UTC
     */
    public static LocalDateTime fromDate(java.util.Date date) {
        return LocalDateTime.ofInstant(date.toInstant(), ZoneOffset.UTC);
    }
}