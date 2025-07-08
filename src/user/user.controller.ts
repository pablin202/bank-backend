import { 
  Controller, 
  Get, 
  Put, 
  Body, 
  UseGuards, 
  HttpCode,
  HttpStatus,
  ValidationPipe,
  Param,
  ParseIntPipe
} from '@nestjs/common';
import { UserService } from './user.service';
import { JwtAuthGuard } from '../auth/jwt-auth.guard';
import { GetUser } from '../auth/get-user.decorator';
import { 
  ApiTags, 
  ApiOperation, 
  ApiResponse, 
  ApiBearerAuth,
  ApiParam
} from '@nestjs/swagger';
import { UserSafeData } from '../auth/interfaces/auth.interface';
import { IsEmail, IsOptional, IsBoolean } from 'class-validator';
import { ApiProperty } from '@nestjs/swagger';

class UpdateUserDto {
  @ApiProperty({ example: 'user@example.com', required: false })
  @IsOptional()
  @IsEmail()
  email?: string;

  @ApiProperty({ example: true, required: false })
  @IsOptional()
  @IsBoolean()
  isActive?: boolean;
}

@ApiTags('Users')
@Controller('users')
@UseGuards(JwtAuthGuard)
@ApiBearerAuth()
export class UserController {
  constructor(private readonly userService: UserService) {}

  @Get('profile')
  @ApiOperation({ summary: 'Get current user profile' })
  @ApiResponse({ status: 200, description: 'User profile retrieved successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getProfile(@GetUser() user: UserSafeData): Promise<UserSafeData> {
    return user;
  }

  @Put('profile')
  @HttpCode(HttpStatus.OK)
  @ApiOperation({ summary: 'Update current user profile' })
  @ApiResponse({ status: 200, description: 'Profile updated successfully' })
  @ApiResponse({ status: 400, description: 'Invalid input data' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async updateProfile(
    @GetUser() user: UserSafeData,
    @Body(ValidationPipe) updateUserDto: UpdateUserDto
  ): Promise<{ message: string; user: UserSafeData }> {
    const updatedUser = await this.userService.update(user.id, updateUserDto);
    const safeUserData = await this.userService.getSafeUserData(updatedUser);
    
    return {
      message: 'Profile updated successfully',
      user: safeUserData
    };
  }

  @Get(':id')
  @ApiOperation({ summary: 'Get user by ID (admin only)' })
  @ApiResponse({ status: 200, description: 'User retrieved successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  @ApiResponse({ status: 404, description: 'User not found' })
  @ApiParam({ name: 'id', description: 'User ID' })
  async getUserById(
    @Param('id', ParseIntPipe) id: number,
    @GetUser() currentUser: UserSafeData
  ): Promise<UserSafeData> {
    // For now, users can only access their own profile
    // TODO: Add admin role check for accessing other users
    if (currentUser.id !== id) {
      throw new Error('Access denied: You can only access your own profile');
    }

    const user = await this.userService.findById(id);
    if (!user) {
      throw new Error('User not found');
    }

    return this.userService.getSafeUserData(user);
  }

  @Get()
  @ApiOperation({ summary: 'Get all users (admin only)' })
  @ApiResponse({ status: 200, description: 'Users retrieved successfully' })
  @ApiResponse({ status: 401, description: 'Unauthorized' })
  async getAllUsers(@GetUser() currentUser: UserSafeData): Promise<UserSafeData[]> {
    // TODO: Add admin role check
    // For now, return empty array as this should be admin-only
    return [];
  }
}
