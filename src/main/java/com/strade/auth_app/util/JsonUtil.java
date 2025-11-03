package com.strade.auth_app.util;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import lombok.extern.slf4j.Slf4j;

import java.util.Map;

/**
 * Utility class for JSON operations
 */
@Slf4j
public final class JsonUtil {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    static {
        MAPPER.registerModule(new JavaTimeModule());
        MAPPER.disable(SerializationFeature.WRITE_DATES_AS_TIMESTAMPS);
    }

    private JsonUtil() {
        throw new IllegalStateException("Utility class");
    }

    /**
     * Convert object to JSON string
     *
     * @param object Object to convert
     * @return JSON string
     */
    public static String toJson(Object object) {
        try {
            return MAPPER.writeValueAsString(object);
        } catch (JsonProcessingException e) {
            log.error("Failed to convert object to JSON", e);
            throw new IllegalArgumentException("JSON conversion failed", e);
        }
    }

    /**
     * Convert object to pretty JSON string
     *
     * @param object Object to convert
     * @return Pretty JSON string
     */
    public static String toPrettyJson(Object object) {
        try {
            return MAPPER.writerWithDefaultPrettyPrinter().writeValueAsString(object);
        } catch (JsonProcessingException e) {
            log.error("Failed to convert object to pretty JSON", e);
            throw new IllegalArgumentException("JSON conversion failed", e);
        }
    }

    /**
     * Parse JSON string to object
     *
     * @param json JSON string
     * @param clazz Target class
     * @return Parsed object
     */
    public static <T> T fromJson(String json, Class<T> clazz) {
        try {
            return MAPPER.readValue(json, clazz);
        } catch (JsonProcessingException e) {
            log.error("Failed to parse JSON", e);
            throw new IllegalArgumentException("JSON parsing failed", e);
        }
    }

    /**
     * Parse JSON string to object with TypeReference
     *
     * @param json JSON string
     * @param typeRef Type reference
     * @return Parsed object
     */
    public static <T> T fromJson(String json, TypeReference<T> typeRef) {
        try {
            return MAPPER.readValue(json, typeRef);
        } catch (JsonProcessingException e) {
            log.error("Failed to parse JSON", e);
            throw new IllegalArgumentException("JSON parsing failed", e);
        }
    }

    /**
     * Parse JSON string to Map
     *
     * @param json JSON string
     * @return Map
     */
    public static Map<String, Object> toMap(String json) {
        return fromJson(json, new TypeReference<Map<String, Object>>() {});
    }

    /**
     * Convert Map to JSON string
     *
     * @param map Map to convert
     * @return JSON string
     */
    public static String fromMap(Map<String, Object> map) {
        return toJson(map);
    }

    /**
     * Get ObjectMapper instance
     *
     * @return ObjectMapper
     */
    public static ObjectMapper getMapper() {
        return MAPPER;
    }
}
