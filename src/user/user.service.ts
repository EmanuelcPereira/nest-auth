import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { CreateUserDto } from './dto/create-user.dto';

@Injectable()
export class UserService {
  constructor(private readonly prisma: PrismaService) {}

  async create(createUserDto: CreateUserDto) {
    const data = {
      ...createUserDto,
      password: await bcrypt.hash(createUserDto.password, 12),
    };

    const createdUser = await this.prisma.user.create({
      data,
    });

    return {
      ...createdUser,
      password: undefined,
    };
  }

  findByEmail(email: string) {
    return this.prisma.user.findUnique({
      where: { email },
    });
  }
}
