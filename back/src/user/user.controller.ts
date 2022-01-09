import {
  Body,
  Controller,
  ForbiddenException,
  Get,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dtos/create-user.dto';
import { LocalAuthGuard } from '../auth/local-auth.guard';
import { AuthService } from '../auth/auth.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { GetUser } from '../auth/get-user.decorator';
import { User } from './entities/user.entity';

@Controller('account')
export class UserController {
  constructor(
    private readonly userService: UserService,
    private readonly authService: AuthService,
  ) {}

  @Post('/join')
  async createUser(@Body() createUserDto: CreateUserDto) {
    const user = await this.userService.findByEmail(createUserDto.email);

    if (user) {
      throw new ForbiddenException('이미 등록된 사용자입니다.');
    }

    const result = await this.userService.createUser(createUserDto);

    return result;
  }

  @UseGuards(LocalAuthGuard)
  @Post('/login')
  async loginUser(@Req() req) {
    const token = await this.authService.login(req.user);
    return token;
  }

  @UseGuards(JwtAuthGuard)
  @Get('/all')
  async allUser() {
    const user = await this.userService.allUser();
    return user;
  }

  // Decorator 테스트
  @UseGuards(JwtAuthGuard)
  @Get('/test')
  async test(@GetUser() user: User) {
    console.log(user);
  }
}
