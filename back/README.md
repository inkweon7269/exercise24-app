## Installation

```bash
$ npm i -g @nestjs/cli
$ nest new <project-name>

# 프로젝트 관련 NPM 패키지 설치
$ npm i @nestjs/typeorm typeorm pg bcryptjs config

$ npm i @nestjs/passport passport passport-local 
$ npm i @nestjs/jwt passport-jwt
$ npm i --save-dev @types/passport-local @types/passport-jwt

$ npm i class-transformer class-validator
$ npm i axios
```



## TypeORM Integration
ormconfig.json
```json
{
  "type": "postgres",
  "host": "localhost",
  "port": 5432,
  "username": "postgres",
  "password": "postgres",
  "database": "exercise-app",
  "entities": ["dist/**/*.entity.{js,ts}"],
  "synchronize": true
}
```
src/app.module.ts
```typescript
import { Module } from '@nestjs/common';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [TypeOrmModule.forRoot()],
})
export class AppModule {}
```



## Auto-validation
src/main.ts
```typescript
import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true,
      forbidNonWhitelisted: true,
      transform: true,
    }),
  );
  await app.listen(8000);
}
bootstrap();
```


## Create User
```bash
$ nest g mo user
$ nest g co user
$ nest g s user
```
src/user/entities/user.entity.ts
```typescript
import { Column, CreateDateColumn, Entity, PrimaryGeneratedColumn } from "typeorm";

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  id: string;
  
  @Column()
  email: string;
  
  @Column()
  password: string;
  
  @Column()
  username: string;
  
  @CreateDateColumn()
  createAt: Date;
}
```
src/user/user.module.ts
```typescript
import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UserService],
  controllers: [UserController],
})
export class UserModule {}
```
src/user/dtos/create-user.dto.ts
```typescript
import { IsEmail, IsNotEmpty, IsString } from 'class-validator';

export class CreateUserDto {
  @IsEmail()
  @IsString()
  @IsNotEmpty()
  email: string;

  @IsString()
  @IsNotEmpty()
  password: string;

  @IsString()
  @IsNotEmpty()
  username: string;
}
```
src/user/user.service.ts
```typescript
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
```
src/user/user.controller.ts
```typescript
import { Body, Controller, ForbiddenException, Post } from '@nestjs/common';
import { UserService } from './user.service';
import { CreateUserDto } from './dtos/create-user.dto';

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
}
```


## Authentication : ID, Password
src/user/user.module.ts
```typescript
import { Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';

@Module({
  imports: [TypeOrmModule.forFeature([User])],
  providers: [UserService],
  controllers: [UserController],
  // exports 추가
  exports: [UserService],
})
export class UserModule {}
```


```bash
$ nest g mo auth
$ nest g s auth
```


src/auth/local-auth.guard.ts
```typescript
import { Injectable } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';

@Injectable()
export class LocalAuthGuard extends AuthGuard('local') {}
```


src/auth/auth.service.ts
```typescript
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
```


src/auth/local.strategy.ts
```typescript
import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { Strategy } from 'passport-local';
import { AuthService } from './auth.service';

@Injectable()
export class LocalStrategy extends PassportStrategy(Strategy) {
  constructor(private authService: AuthService) {
    super({
      usernameField: 'email',
      passwordField: 'password',
    });
  }

  async validate(email: string, password: string): Promise<any> {
    const payload = { email, password };
    const user = await this.authService.validateUser(payload);
    
    return user;
  }
}
```



src/auth/auth.module.ts
```typescript
import { forwardRef, Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { UserModule } from '../user/user.module';
import { PassportModule } from '@nestjs/passport';
import { LocalStrategy } from './local.strategy';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from '../user/entities/user.entity';

@Module({
  imports: [
    forwardRef(() => UserModule),
    PassportModule,
    TypeOrmModule.forFeature([User]),
  ],
  providers: [AuthService, LocalStrategy],
  exports: [AuthService],
})
export class AuthModule {}
```



src/user/user.module.ts
```typescript
import { forwardRef, Module } from '@nestjs/common';
import { UserService } from './user.service';
import { UserController } from './user.controller';
import { TypeOrmModule } from '@nestjs/typeorm';
import { User } from './entities/user.entity';
import { AuthModule } from '../auth/auth.module';

@Module({
  imports: [
    forwardRef(() => AuthModule), 
    TypeOrmModule.forFeature([User])
  ],
  providers: [UserService],
  controllers: [UserController],
  exports: [UserService],
})
export class UserModule {}
```



src/user/user.controller.ts
```typescript
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
```

## Contact
- Resume - [Inkweon Kim](https://docs.google.com/document/d/1Ca2ndJ7stlcx4lKaCI_YGVvS5aNuP56nOnwj3bLahHU/edit?usp=sharing)
- Facebook - [facebook.com/inkweon7269](https://www.facebook.com/inkweon7269)
- Linkedin - [linkedin.com/in/inkweon7269](https://www.linkedin.com/in/inkweon7269/)