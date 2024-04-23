import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import * as request from 'supertest';
import { JwtPayload } from '../interface/jwt-payload';
import { AuthService } from '../auth.service';

@Injectable()
export class AuthGuard implements CanActivate {

  constructor(private jwtService: JwtService,
    private authService: AuthService,
  ) { }

  async canActivate(context: ExecutionContext,): Promise<boolean> {

    const request = context.switchToHttp().getRequest();
    const token = this.extractTokenFromHeader(request);
    if (!token) {
      throw new UnauthorizedException('No hay token en la peteción');
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(
        token,
        { secret: process.env.JWT_SEED }
      );

      const user = await this.authService.findUserById(payload.id);
      if (!user) throw new UnauthorizedException('User does not exists');
      if (!user.isActive) throw new UnauthorizedException('User is not active');

      request['user'] = user;



    } catch (error) {
      throw new UnauthorizedException();
    }
    // 💡 We're assigning the payload to the request object here
    // so that we can access it in our route handlers

    return Promise.resolve(true);
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const [type, token] = request.headers['authorization']?.split(' ') ?? [];
    return type === 'Bearer' ? token : undefined;
  }

}
