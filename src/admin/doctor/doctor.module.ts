import { Module } from '@nestjs/common';
import { DoctorService } from './doctor.service';
import { DoctorController } from './doctor.controller';
import { Doctor } from 'src/entities/doctor.entity';
import { Department } from 'src/entities/department.entity';
import { TypeOrmModule } from '@nestjs/typeorm';

@Module({
  imports: [TypeOrmModule.forFeature([Doctor, Department]),],
  controllers: [DoctorController],
  providers: [DoctorService],
})
export class DoctorModule { }
