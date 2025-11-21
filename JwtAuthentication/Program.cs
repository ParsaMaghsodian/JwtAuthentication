using FluentValidation;
using JwtAuthentication.DTO;
using JwtAuthentication.Identity;
using JwtAuthentication.Identity.Models;
using JwtAuthentication.Services;
using JwtAuthentication.Shared;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Identity.Web;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

builder.Services.Configure<JwtConfiguration>(builder.Configuration.GetSection(nameof(JwtConfiguration)));
// configure EF Core DbContext 
builder.Services.AddDbContext<UserDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("Identity")));
// Add Identity and wire up EF stores
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
    {
        options.SignIn.RequireConfirmedAccount = false;
    })
    .AddEntityFrameworkStores<UserDbContext>()
    .AddDefaultTokenProviders();
builder.Services.AddScoped<IUserService, UserService>();
// Authentication 
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(options =>
{
    options.TokenValidationParameters.ValidIssuer = builder.Configuration["Jwt:Issuer"];
    options.TokenValidationParameters.ValidAudience = builder.Configuration["Jwt:Audience"];
    options.TokenValidationParameters.IssuerSigningKey = new SymmetricSecurityKey(
       Encoding.UTF8.GetBytes(builder.Configuration["JwtConfiguration:Audience"]!));
});


builder.Services.AddAuthorization(options => options.AddPolicy("RequiredAdminRole", policy => policy.RequireRole(Role.Admin)));
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();
builder.Services.AddValidatorsFromAssemblyContaining<UserRegisterationRequest>();
var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// Ensure authentication runs before authorization
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
