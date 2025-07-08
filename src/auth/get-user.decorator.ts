import { createParamDecorator, ExecutionContext } from '@nestjs/common';
import { UserSafeData } from './interfaces/auth.interface';

export const GetUser = createParamDecorator(
  (data: keyof UserSafeData | undefined, ctx: ExecutionContext): UserSafeData | any => {
    const request = ctx.switchToHttp().getRequest();
    const user = request.user;
    
    return data ? user?.[data] : user;
  },
);