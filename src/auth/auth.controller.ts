import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto/auth.dto';
import { Tokens } from './types';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('/signup')
  signup(@Body() authDto: AuthDto): Promise<Tokens> {
    return this.authService.signup(authDto);
  }

  @Post('/signin')
  signin() {
    return this.authService.signup();
  }

  @Post('/logout')
  logout() {
    return this.authService.signup();
  }

  @Post('/refresh')
  refreshTokens() {
    return this.authService.signup();
  }
}
