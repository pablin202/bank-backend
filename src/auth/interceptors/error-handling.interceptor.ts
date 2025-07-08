import {
  Injectable,
  NestInterceptor,
  ExecutionContext,
  CallHandler,
  HttpException,
  HttpStatus,
  Logger,
} from '@nestjs/common';
import { Observable, throwError } from 'rxjs';
import { catchError } from 'rxjs/operators';

@Injectable()
export class ErrorHandlingInterceptor implements NestInterceptor {
  private readonly logger = new Logger(ErrorHandlingInterceptor.name);

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    return next.handle().pipe(
      catchError((error) => {
        const request = context.switchToHttp().getRequest();
        const response = context.switchToHttp().getResponse();

        // Log the error
        this.logger.error(
          `Error in ${request.method} ${request.url}:`,
          error.stack || error.message,
        );

        // Handle different types of errors
        if (error instanceof HttpException) {
          return throwError(() => error);
        }

        // Handle database errors
        if (error.code === '23505') { // PostgreSQL unique violation
          return throwError(() => new HttpException(
            'Resource already exists',
            HttpStatus.CONFLICT,
          ));
        }

        if (error.code === '23503') { // PostgreSQL foreign key violation
          return throwError(() => new HttpException(
            'Referenced resource not found',
            HttpStatus.BAD_REQUEST,
          ));
        }

        // Handle validation errors
        if (error.name === 'ValidationError') {
          return throwError(() => new HttpException(
            {
              statusCode: HttpStatus.BAD_REQUEST,
              message: 'Validation failed',
              errors: error.details,
            },
            HttpStatus.BAD_REQUEST,
          ));
        }

        // Handle JWT errors
        if (error.name === 'JsonWebTokenError') {
          return throwError(() => new HttpException(
            'Invalid token',
            HttpStatus.UNAUTHORIZED,
          ));
        }

        if (error.name === 'TokenExpiredError') {
          return throwError(() => new HttpException(
            'Token expired',
            HttpStatus.UNAUTHORIZED,
          ));
        }

        // Default to internal server error
        return throwError(() => new HttpException(
          'Internal server error',
          HttpStatus.INTERNAL_SERVER_ERROR,
        ));
      }),
    );
  }
}