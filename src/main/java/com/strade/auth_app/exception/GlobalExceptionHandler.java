package com.strade.auth_app.exception;

import com.strade.auth_app.dto.response.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.HashMap;
import java.util.Map;

/**
 * Global exception handler
 */
@RestControllerAdvice
@Slf4j
public class GlobalExceptionHandler {

    /**
     * Handle AuthException
     */
    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ApiResponse<Void>> handleAuthException(AuthException ex) {
        log.error("AuthException: code={}, message={}", ex.getCode(), ex.getMessage());

        ApiResponse<Void> response = ApiResponse.error(
                ApiResponse.ApiError.builder()
                        .code(ex.getCode()) // Use custom code from exception
                        .message(ex.getMessage())
                        .details((String) ex.getDetails())
                        .build()
        );

        // Use HTTP status from ErrorCode
        HttpStatus httpStatus = ex.getHttpStatus();

        return ResponseEntity.status(httpStatus).body(response);
    }

    /**
     * Handle TokenException
     */
    @ExceptionHandler(TokenException.class)
    public ResponseEntity<ApiResponse<Void>> handleTokenException(TokenException ex) {
        log.error("TokenException: code={}, message={}", ex.getCode(), ex.getMessage());

        ApiResponse<Void> response = ApiResponse.error(
                ApiResponse.ApiError.builder()
                        .code(ex.getCode())
                        .message(ex.getMessage())
                        .details((String) ex.getDetails())
                        .build()
        );

        return ResponseEntity.status(ex.getHttpStatus()).body(response);
    }

    /**
     * Handle validation errors
     */
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ApiResponse<Void>> handleValidationException(
            MethodArgumentNotValidException ex
    ) {
        Map<String, String> errors = new HashMap<>();
        ex.getBindingResult().getAllErrors().forEach(error -> {
            String fieldName = ((FieldError) error).getField();
            String errorMessage = error.getDefaultMessage();
            errors.put(fieldName, errorMessage);
        });

        ApiResponse<Void> response = ApiResponse.error(
                ApiResponse.ApiError.builder()
                        .code(ErrorCode.VALIDATION_ERROR.getCode())
                        .message("Validation failed")
                        .details(errors.toString())
                        .build()
        );

        return ResponseEntity.badRequest().body(response);
    }

    /**
     * Handle generic exceptions
     */
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ApiResponse<Void>> handleGenericException(Exception ex) {
        log.error("Unexpected error", ex);

        ApiResponse<Void> response = ApiResponse.error(
                ApiResponse.ApiError.builder()
                        .code(ErrorCode.INTERNAL_SERVER_ERROR.getCode())
                        .message("An unexpected error occurred")
                        .details(ex.getMessage())
                        .build()
        );

        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(response);
    }
}