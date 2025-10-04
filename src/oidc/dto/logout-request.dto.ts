import { IsOptional, IsString } from 'class-validator';

export class LogoutRequestDto {
  @IsOptional()
  @IsString()
  post_logout_redirect_uri?: string;

  @IsOptional()
  @IsString()
  state?: string;

  @IsOptional()
  @IsString()
  id_token_hint?: string;

  @IsOptional()
  @IsString()
  session_id?: string;
}
