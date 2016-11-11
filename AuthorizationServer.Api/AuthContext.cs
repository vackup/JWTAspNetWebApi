﻿using System.Data.Entity;
using AuthorizationServer.Api.Entities;
using Microsoft.AspNet.Identity.EntityFramework;

namespace AuthorizationServer.Api
{
    public class AuthContext : IdentityDbContext<IdentityUser>
    {
        public AuthContext()
            : base("AuthContext")
        {

        }

        public DbSet<Client> Clients { get; set; }
        public DbSet<RefreshToken> RefreshTokens { get; set; }
    }
}