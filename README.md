# runmate

Guia Completo: Implementação de Autenticação entre Microsserviços em .NET

Este guia detalha todo o processo que realizamos para criar uma arquitetura de microsserviços com autenticação compartilhada usando JWT em .NET.

1. Estrutura da Solução

Criamos uma solução com três projetos principais:

RunMate.Authentication - Microsserviço de autenticação
RunMate.Microservice - Microsserviço de exemplo que consome a autenticação
RunMate.Shared.Auth - Biblioteca compartilhada para autenticação
2. Biblioteca Compartilhada (RunMate.Shared.Auth)
2.1. Criação do Projeto
dotnet new classlib -n RunMate.Shared.Auth
dotnet sln add RunMate.Shared.Auth/RunMate.Shared.Auth.csproj

2.2. Instalação de Pacotes NuGet
cd RunMate.Shared.Auth
dotnet add package Microsoft.AspNetCore.Authentication.JwtBearer
dotnet add package Microsoft.Extensions.DependencyInjection

2.3. Implementação da Classe JwtAuthExtensions

Criamos o arquivo JwtAuthExtensions.cs com o seguinte conteúdo:

using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using System.Text;

namespace RunMate.Shared.Auth
{
  public static class JwtAuthExtensions
  {
      public static IServiceCollection AddSharedJwtAuthentication(
          this IServiceCollection services, 
          IConfiguration configuration)
      {
          services.AddAuthentication(options =>
          {
              options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
              options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
          })
          .AddJwtBearer(options =>
          {
              options.TokenValidationParameters = new TokenValidationParameters
              {
                  ValidateIssuer = true,
                  ValidateAudience = true,
                  ValidateLifetime = true,
                  ValidateIssuerSigningKey = true,
                  ValidIssuer = configuration["Jwt:Issuer"],
                  ValidAudience = configuration["Jwt:Audience"],
                  IssuerSigningKey = new SymmetricSecurityKey(
                      Encoding.UTF8.GetBytes(configuration["Jwt:Key"]))
              };
          });

          return services;
      }
  }

  public static class ClaimsPrincipalExtensions
  {
      public static string GetUserId(this System.Security.Claims.ClaimsPrincipal user)
      {
          return user.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
      }
      
      public static string GetUserName(this System.Security.Claims.ClaimsPrincipal user)
      {
          return user.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
      }
      
      public static string GetUserRole(this System.Security.Claims.ClaimsPrincipal user)
      {
          return user.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;
      }
  }
}

3. Serviço de Autenticação (RunMate.Authentication)
3.1. Estrutura de Pastas
📂 RunMate.Authentication
 📂 RunMate.API
    📂 Controllers
       📄 AuthController.cs
       📄 UserController.cs
 📂 RunMate.Application
    📂 DTOs
       📄 LoginRequestDto.cs
       📄 LoginResponseDto.cs
    📂 Interfaces
       📄 IAuthService.cs
       📄 IUserService.cs
    📂 Services
       📄 AuthService.cs
       📄 UserService.cs
 📂 RunMate.Domain
    📂 Entities
       📄 User.cs
    📂 Enums
       📄 UserRole.cs
 📂 RunMate.Infrastructure
    📂 Persistence
       📄 RunMateContext.cs
    📂 Configurations
    📂 Migrations
 📂 Properties
    📄 launchSettings.json
 📄 Program.cs
 📄 appsettings.json

3.2. Configuração do appsettings.json
{
"ConnectionStrings": {
  "RunMateDatabase": "Host=localhost;Database=runmate_db;Username=postgres;Password=2002"
},
"Logging": {
  "LogLevel": {
    "Default": "Information",
    "Microsoft.AspNetCore": "Warning"
  }
},
"Jwt": {
  "Key": "Sua_Chave_Secreta_Muito_Longa_E_Segura_Pelo_Menos_32_Caracteres_123456789",
  "Issuer": "RunMate",
  "Audience": "RunMateUsers",
  "DurationInMinutes": 60,
  "RefreshTokenValidityInDays": 7
},
"AllowedHosts": "*"
}

3.3. Configuração do launchSettings.json
{
"$schema": "http://json.schemastore.org/launchsettings.json",
"iisSettings": {
  "windowsAuthentication": false,
  "anonymousAuthentication": true,
  "iisExpress": {
    "applicationUrl": "http://localhost:43398",
    "sslPort": 44301
  }
},
"profiles": {
  "https": {
    "commandName": "Project",
    "dotnetRunMessages": true,
    "launchBrowser": true,
    "launchUrl": "swagger",
    "applicationUrl": "https://localhost:7001;http://localhost:5001",
    "environmentVariables": {
      "ASPNETCORE_ENVIRONMENT": "Development"
    }
  },
  "http": {
    "commandName": "Project",
    "dotnetRunMessages": true,
    "launchBrowser": true,
    "launchUrl": "swagger",
    "applicationUrl": "http://localhost:5001",
    "environmentVariables": {
      "ASPNETCORE_ENVIRONMENT": "Development"
    }
  },
  "IIS Express": {
    "commandName": "IISExpress",
    "launchBrowser": true,
    "launchUrl": "swagger",
    "environmentVariables": {
      "ASPNETCORE_ENVIRONMENT": "Development"
    }
  }
}
}

3.4. Configuração do Program.cs
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using RunMate.RunMate.Infrastructure.Persistence;
using System.Text;
using RunMate.RunMate.Application.Interfaces;
using RunMate.RunMate.Application.Services;
using Microsoft.AspNetCore.Cors;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddDbContext<RunMateContext>(options =>
options.UseNpgsql(builder.Configuration.GetConnectionString("RunMateDatabase")));

// Adicionar CORS para permitir requisições de outros microsserviços
builder.Services.AddCors(options =>
{
  options.AddPolicy("AllowAll",
      builder =>
      {
          builder.AllowAnyOrigin()
                 .AllowAnyMethod()
                 .AllowAnyHeader();
      });
});

// Configuração da autenticação JWT
builder.Services.AddAuthentication(options =>
{
  options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
  options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
  options.TokenValidationParameters = new TokenValidationParameters
  {
      ValidateIssuer = true,
      ValidateAudience = true,
      ValidateLifetime = true,
      ValidateIssuerSigningKey = true,
      ValidIssuer = builder.Configuration["Jwt:Issuer"],
      ValidAudience = builder.Configuration["Jwt:Audience"],
      IssuerSigningKey = new SymmetricSecurityKey(
          Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]))
  };
});

// Registrar serviços
builder.Services.AddScoped<IAuthService, AuthService>();
builder.Services.AddScoped<IUserService, UserService>();

builder.Services.AddControllers();

// Configurar Swagger para suportar JWT
builder.Services.AddSwaggerGen(c =>
{
  c.SwaggerDoc("v1", new OpenApiInfo { Title = "RunMate API", Version = "v1" });

  // Adicionar configuração de segurança para Swagger
  c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
  {
      Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
      Name = "Authorization",
      In = ParameterLocation.Header,
      Type = SecuritySchemeType.ApiKey,
      Scheme = "Bearer"
  });

  c.AddSecurityRequirement(new OpenApiSecurityRequirement
 {
     {
         new OpenApiSecurityScheme
         {
             Reference = new OpenApiReference
             {
                 Type = ReferenceType.SecurityScheme,
                 Id = "Bearer"
             }
         },
         new string[] {}
     }
 });
});

builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
  app.UseSwagger();
  app.UseSwaggerUI();
}

// Adicionar middleware CORS antes da autenticação
app.UseCors("AllowAll");

// Importante: UseAuthentication deve vir antes de UseAuthorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

3.5. Implementação do AuthController
using Microsoft.AspNetCore.Mvc;
using RunMate.RunMate.Application.DTOs;
using RunMate.RunMate.Application.DTOs.UserDTOs;
using RunMate.RunMate.Application.Interfaces;

namespace RunMate.RunMate.API.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class AuthController : ControllerBase
  {
      private readonly IAuthService _authService;
      private readonly IUserService _userService;

      public AuthController(IAuthService authService, IUserService userService)
      {
          _authService = authService;
          _userService = userService;
      }

      [HttpPost("login")]
      public async Task<IActionResult> Login([FromBody] LoginRequestDto request)
      {
          if (!ModelState.IsValid)
          {
              return BadRequest(ModelState);
          }

          var response = await _authService.Login(request);

          if (response == null)
          {
              return Unauthorized(new { message = "Nome de usuário ou senha inválidos" });
          }

          return Ok(response);
      }

      [HttpPost("register")]
      public async Task<IActionResult> Register([FromBody] RegisterUserDto request)
      {
          if (!ModelState.IsValid)
          {
              return BadRequest(ModelState);
          }

          var result = await _userService.CreateUserAsync(request);

          if (!result)
          {
              return BadRequest(new { message = "Nome de usuário ou email já existe" });
          }

          return Ok(new { message = "Usuário registrado com sucesso" });
      }
  }
}

3.6. Implementação do AuthService
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RunMate.Domain.Entities;
using RunMate.RunMate.Application.DTOs;
using RunMate.RunMate.Application.Interfaces;
using RunMate.RunMate.Infrastructure.Persistence;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RunMate.RunMate.Application.Services
{
  public class AuthService : IAuthService
  {
      private readonly IConfiguration _configuration;
      private readonly RunMateContext _context;

      public AuthService(IConfiguration configuration, RunMateContext context)
      {
          _configuration = configuration;
          _context = context;
      }

      public async Task<LoginResponseDto> Login(LoginRequestDto request)
      {
          var user = await _context.Users.FirstOrDefaultAsync(u =>
              u.Username == request.Username && u.IsActive);

          if (user == null || !VerifyPassword(request.Password, user.PasswordHash))
          {
              return null; // Retornará 401 Unauthorized no controller
          }

          // Atualiza último login
          user.LastLogin = DateTime.UtcNow;
          await _context.SaveChangesAsync();

          // Gera o token JWT
          var token = GenerateJwtToken(user);

          return new LoginResponseDto
          {
              Token = token,
              Username = user.Username,
              Email = user.Email,
              Role = user.Role.ToString(),
              Expiration = DateTime.UtcNow.AddHours(1) // Token válido por 1 hora
          };
      }

      public string GenerateJwtToken(User user)
      {
          var tokenHandler = new JwtSecurityTokenHandler();
          var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);

          var tokenDescriptor = new SecurityTokenDescriptor
          {
              Subject = new ClaimsIdentity(new[]
              {
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Name, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(ClaimTypes.Role, user.Role.ToString())
            }),
              Expires = DateTime.UtcNow.AddHours(1),
              Issuer = _configuration["Jwt:Issuer"],
              Audience = _configuration["Jwt:Audience"],
              SigningCredentials = new SigningCredentials(
                  new SymmetricSecurityKey(key),
                  SecurityAlgorithms.HmacSha256Signature)
          };

          var token = tokenHandler.CreateToken(tokenDescriptor);
          return tokenHandler.WriteToken(token);
      }

      public string HashPassword(string password)
      {
          return BCrypt.Net.BCrypt.HashPassword(password);
      }

      public bool VerifyPassword(string password, string passwordHash)
      {
          return BCrypt.Net.BCrypt.Verify(password, passwordHash);
      }
  }
}

4. Microsserviço de Exemplo (RunMate.Microservice)
4.1. Estrutura de Pastas
📂 RunMate.Microservice
 📂 Controllers
    📄 TestController.cs
 📂 Properties
    📄 launchSettings.json
 📄 Program.cs
 📄 appsettings.json

4.2. Configuração do appsettings.json
{
"Logging": {
  "LogLevel": {
    "Default": "Information",
    "Microsoft.AspNetCore": "Warning"
  }
},
"Jwt": {
  "Key": "Sua_Chave_Secreta_Muito_Longa_E_Segura_Pelo_Menos_32_Caracteres_123456789",
  "Issuer": "RunMate",
  "Audience": "RunMateUsers",
  "DurationInMinutes": 60
},
"AllowedHosts": "*"
}

4.3. Configuração do launchSettings.json
{
"$schema": "http://json.schemastore.org/launchsettings.json",
"iisSettings": {
  "windowsAuthentication": false,
  "anonymousAuthentication": true,
  "iisExpress": {
    "applicationUrl": "http://localhost:43399",
    "sslPort": 44302
  }
},
"profiles": {
  "https": {
    "commandName": "Project",
    "dotnetRunMessages": true,
    "launchBrowser": true,
    "launchUrl": "swagger",
    "applicationUrl": "https://localhost:7002;http://localhost:5002",
    "environmentVariables": {
      "ASPNETCORE_ENVIRONMENT": "Development"
    }
  },
  "http": {
    "commandName": "Project",
    "dotnetRunMessages": true,
    "launchBrowser": true,
    "launchUrl": "swagger",
    "applicationUrl": "http://localhost:5002",
    "environmentVariables": {
      "ASPNETCORE_ENVIRONMENT": "Development"
    }
  },
  "IIS Express": {
    "commandName": "IISExpress",
    "launchBrowser": true,
    "launchUrl": "swagger",
    "environmentVariables": {
      "ASPNETCORE_ENVIRONMENT": "Development"
    }
  }
}
}

4.4. Configuração do Program.cs
using Microsoft.OpenApi.Models;
using RunMate.Shared.Auth;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container
builder.Services.AddControllers();

// Adicione a autenticação JWT compartilhada
builder.Services.AddSharedJwtAuthentication(builder.Configuration);

// Configure Swagger com suporte para JWT
builder.Services.AddSwaggerGen(c =>
{
  c.SwaggerDoc("v1", new OpenApiInfo { Title = "RunMate Example Service", Version = "v1" });

  // Adicionar configuração de segurança para Swagger
  c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
  {
      Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
      Name = "Authorization",
      In = ParameterLocation.Header,
      Type = SecuritySchemeType.ApiKey,
      Scheme = "Bearer"
  });

  c.AddSecurityRequirement(new OpenApiSecurityRequirement
  {
      {
          new OpenApiSecurityScheme
          {
              Reference = new OpenApiReference
              {
                  Type = ReferenceType.SecurityScheme,
                  Id = "Bearer"
              }
          },
          new string[] {}
      }
  });
});

builder.Services.AddEndpointsApiExplorer();

var app = builder.Build();

// Configure the HTTP request pipeline
if (app.Environment.IsDevelopment())
{
  app.UseSwagger();
  app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Importante: UseAuthentication deve vir antes de UseAuthorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();

4.5. Implementação do TestController
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace RunMate.Microservice.Controllers
{
  [ApiController]
  [Route("api/[controller]")]
  public class TestController : ControllerBase
  {
      [HttpGet("public")]
      public IActionResult GetPublic()
      {
          return Ok(new { message = "Este é um endpoint público" });
      }

      [HttpGet("protected")]
      [Authorize]
      public IActionResult GetProtected()
      {
          var userId = User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
          var username = User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
          var email = User.FindFirst(System.Security.Claims.ClaimTypes.Email)?.Value;
          var role = User.FindFirst(System.Security.Claims.ClaimTypes.Role)?.Value;
          
          return Ok(new { 
              message = "Este é um endpoint protegido", 
              userId, 
              username,
              email,
              role
          });
      }

      [HttpGet("admin")]
      [Authorize(Roles = "Admin")]
      public IActionResult GetAdmin()
      {
          return Ok(new { message = "Este é um endpoint apenas para administradores" });
      }

      [HttpGet("claims")]
      [Authorize]
      public IActionResult GetClaims()
      {
          var claims = User.Claims.Select(c => new { c.Type, c.Value }).ToList();
          return Ok(new { claims });
      }
  }
}

5. Configuração para Iniciar Múltiplos Projetos
Clique com o botão direito na solução
Selecione "Configure Startup Projects..."
Escolha "Multiple startup projects"
Defina:
RunMate.Authentication: "Start"
RunMate.Microservice: "Start"
RunMate.Shared.Auth: "None"
Clique em "OK"
6. Testando a Autenticação entre Microsserviços
6.1. Obter um Token JWT
Execute a solução (F5)
Acesse o Swagger do serviço de autenticação: https://localhost:7001/swagger
Use o endpoint POST /api/Auth/login com credenciais válidas:
{
  "username": "seu_usuario",
  "password": "sua_senha"
}

Copie o token JWT da resposta
6.2. Usar o Token para Acessar o Endpoint Protegido
Acesse o Swagger do microsserviço: https://localhost:7002/swagger
Clique no botão "Authorize" no topo da página
Digite Bearer seguido do token JWT (exemplo: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...)
Clique em "Authorize" e depois em "Close"
Teste o endpoint GET /api/Test/protected
Você deve receber uma resposta 200 OK com as informações do usuário
7. Pontos Importantes a Lembrar
7.1. Estrutura de Pastas
Cada serviço deve ter sua própria pasta Properties com seu próprio arquivo launchSettings.json
A pasta Properties é especial e deve manter esse nome exato
7.2. Configurações JWT
A mesma chave JWT deve ser usada em todos os serviços
As configurações de emissor (Issuer) e público (Audience) devem ser idênticas em todos os serviços
7.3. Formato do Token
O token JWT deve ser enviado com o prefixo "Bearer " no cabeçalho Authorization
7.4. Portas
Cada serviço deve usar portas diferentes para evitar conflitos:
RunMate.Authentication: 7001/5001
RunMate.Microservice: 7002/5002
7.5. Claims
As claims são mapeadas para os tipos padrão do .NET:
nameid → ClaimTypes.NameIdentifier
unique_name → ClaimTypes.Name
email → ClaimTypes.Email
role → ClaimTypes.Role
8. Próximos Passos
Implementar Refresh Tokens: Para permitir que os usuários obtenham novos tokens sem fazer login novamente
Adicionar Validações: Usar FluentValidation para validar entradas
Implementar Logging: Adicionar logging centralizado para auditoria
Implementar Health Checks: Para monitorar a saúde dos serviços
Implementar API Gateway: Para centralizar o roteamento e a autenticação
Containerização: Usar Docker para containerizar os serviços
Orquestração: Usar Kubernetes para orquestrar os containers
CI/CD: Configurar pipelines de integração e entrega contínua

Este guia completo cobre todos os aspectos da implementação de autenticação entre microsserviços usando JWT em .NET, desde a criação da biblioteca compartilhada até o teste da autenticação entre os serviços.
