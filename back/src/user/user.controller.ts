import {
  Body,
  Controller,
  ForbiddenException,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dtos/create-user.dto';
import { LocalAuthGuard } from '../auth/local-auth.guard';

@Controller('account')
export class UserController {
  constructor(private readonly userService: UserService) {}

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
    console.log('req', req.user);
  }
}
