using System.Security.Cryptography;
using System.Text;
using API.Data;
using API.DTOs;
using API.Entities;
using API.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace API.Controllers
{
    [Authorize]
    public class AccountController : BaseApiController
    {
        private readonly DataContext _context;
        private readonly ITokenService _tokenService;
        public AccountController(DataContext context, ITokenService tokenService)
        {
            _tokenService = tokenService;
            _context = context;
            
        }


        [AllowAnonymous]
        [HttpPost("register")]
        public async Task<ActionResult<UserDto>> Register(RegisterDto registerDto) 
        {
            if(await UsersExists(registerDto.UserName)) return BadRequest("Username is taken!");            

            using var hmac = new HMACSHA512();

            var user = new AppUser
            {
                UserName = registerDto.UserName.ToLower(),
                PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
                PasswordSalt = hmac.Key
            };
            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };            
         }

         private async Task<bool> UsersExists(string username)
         {
            return await _context.Users.AnyAsync(x=>x.UserName==username.ToLower());

         }

        [HttpPost("login")]
        public async Task<ActionResult<UserDto>> Login(LoginDto logindto) 
        {
            var user = await _context.Users.SingleOrDefaultAsync(x=>x.UserName==logindto.UserName);

            if(user==null) return Unauthorized("Username is Invalid!");

            using var hmac = new HMACSHA512(user.PasswordSalt);

            var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(logindto.Password));

            for(int i=0; i<computedHash.Length; i++)
            {
                if(computedHash[i]!=user.PasswordHash[i]) return Unauthorized("Password mismatch");
            }

             return new UserDto{
                Username = user.UserName,
                Token = _tokenService.CreateToken(user)
            };               
         }
        
    }
}