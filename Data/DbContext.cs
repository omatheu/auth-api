﻿using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthenticationAuthorization.Data
{
    public class AuthDbContext : IdentityDbContext<IdentityUser>
    {

        public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
        {
        }

    }
}