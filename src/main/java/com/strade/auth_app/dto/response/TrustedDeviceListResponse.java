package com.strade.auth_app.dto.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

/**
 * List of trusted devices response
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@JsonInclude(JsonInclude.Include.NON_NULL)
public class TrustedDeviceListResponse {

    private List<TrustedDeviceResponse> devices;
    private Integer totalCount;
    private Integer activeCount;
    private Integer maxAllowed;
    private Integer availableSlots;
}
