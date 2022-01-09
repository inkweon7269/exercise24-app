import { ForbiddenException, Injectable } from '@nestjs/common';
import { UserService } from '../user/user.service';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class AuthService {
  constructor(private userService: UserService) {}

  async validateUser(payload): Promise<any> {
    const { email, password } = payload;
    const user = await this.userService.findByEmail(email);

    if (!user) {
      throw new ForbiddenException('등록되지 않은 사용자입니다.');
    }

    if (!(await bcrypt.compare(password, user.password))) {
      throw new ForbiddenException('비밀번호가 일치하지 않습니다.');
    }

    return user;
  }
}
