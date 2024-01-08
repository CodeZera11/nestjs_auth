import { Injectable } from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto/auth.dto';
import * as bcrypt from 'bcrypt';
import { Tokens } from './types';

@Injectable()
export class AuthService {
  constructor(private readonly prisma: PrismaService) {}

  hashData(data: string) {
    return bcrypt.hash(data, 10);
  }
  async signup(authDto: AuthDto): Promise<Tokens> {
    const hashedPassword = await this.hashData(authDto.password);
    const newUser = await this.prisma.user.create({
      data: {
        email: authDto.email,
        hash: hashedPassword,
      },
    });
  }

  signin() {}

  logout() {}

  refreshTokens() {}
}
