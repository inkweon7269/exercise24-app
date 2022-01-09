import { Injectable } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { Repository } from 'typeorm';
import { CreateUserDto } from './dtos/create-user.dto';
import * as bcrypt from 'bcryptjs';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  async allUser() {
    return this.userRepository.find();
  }

  async createUser(createUserDto: CreateUserDto) {
    const salt = await bcrypt.genSalt();
    const hashedPassword = await bcrypt.hash(createUserDto.password, salt);
    const user = await this.userRepository.create({
      email: createUserDto.email,
      password: hashedPassword,
      username: createUserDto.username,
    });

    const { password, ...result } = await this.userRepository.save(user);

    return result;
  }

  async findByEmail(email) {
    const user = await this.userRepository.findOne({ email });
    return user;
  }

  async findById(id) {
    const user = await this.userRepository.findOne({ id });
    return user;
  }
}
