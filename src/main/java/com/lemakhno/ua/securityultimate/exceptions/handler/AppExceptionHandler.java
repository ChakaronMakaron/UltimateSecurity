package com.lemakhno.ua.securityultimate.exceptions.handler;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.context.request.WebRequest;

import com.lemakhno.ua.securityultimate.exceptions.BadTokenException;
import com.lemakhno.ua.securityultimate.response.ErrorResponse;

@ControllerAdvice
public class AppExceptionHandler {
    
    @ExceptionHandler({ Exception.class })
    public ResponseEntity<ErrorResponse> handleBadTokenException(BadTokenException ex, WebRequest request) {

        ErrorResponse errorResponse = new ErrorResponse();
        errorResponse.setMessage(ex.getMessage());
        errorResponse.setStatus(403);

        ResponseEntity<ErrorResponse> responseEntity = new ResponseEntity<ErrorResponse>(errorResponse, HttpStatus.FORBIDDEN);

        return responseEntity;
    }
}


