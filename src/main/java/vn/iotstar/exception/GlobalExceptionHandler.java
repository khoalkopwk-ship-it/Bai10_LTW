package vn.iotstar.exception;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {
    @ExceptionHandler(InsufficientAuthenticationException.class)
    public ProblemDetail authenticationRequired(InsufficientAuthenticationException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Vui lòng đăng nhập và gửi Bearer token.");
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ProblemDetail invalidToken(InvalidTokenException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, e.getMessage());
    }

    @ExceptionHandler(AccountStatusException.class)
    public ProblemDetail accountStatus(AccountStatusException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "Tài khoản bị khóa hoặc không còn hiệu lực.");
    }

    @ExceptionHandler(AuthenticationException.class)
    public ProblemDetail authentication(AuthenticationException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.UNAUTHORIZED, "Email hoặc mật khẩu không đúng.");
    }

    @ExceptionHandler(AccessDeniedException.class)
    public ProblemDetail accessDenied(AccessDeniedException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.FORBIDDEN, "Không có quyền truy cập tài nguyên.");
    }

    @ExceptionHandler({MethodArgumentNotValidException.class, HttpMessageNotReadableException.class})
    public ProblemDetail invalidInput(Exception e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.BAD_REQUEST, "Dữ liệu không hợp lệ. Kiểm tra email, mật khẩu và họ tên.");
    }

    @ExceptionHandler(DataIntegrityViolationException.class)
    public ProblemDetail duplicateUser(DataIntegrityViolationException e) {
        return ProblemDetail.forStatusAndDetail(HttpStatus.CONFLICT, "Không thể tạo tài khoản. Email có thể đã được sử dụng.");
    }
}
