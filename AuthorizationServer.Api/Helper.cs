using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Threading.Tasks;
using System.Web.Configuration;
using Microsoft.Owin.Security;

namespace AuthorizationServer.Api
{
    public class Helper
    {
        public static string GetHash(string input)
        {
            HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider();

            byte[] byteValue = System.Text.Encoding.UTF8.GetBytes(input);

            byte[] byteHash = hashAlgorithm.ComputeHash(byteValue);

            return Convert.ToBase64String(byteHash);
        }

        public static AuthenticationTicket GetJwtAuthenticationTicket(string userName, List<string> roleList, string clientId)
        {
            var identity = new ClaimsIdentity("JWT");

            identity.AddClaim(new Claim(ClaimTypes.Name, userName));
            identity.AddClaim(new Claim("sub", userName));


            foreach (var role in roleList)
            {
                identity.AddClaim(new Claim(ClaimTypes.Role, role));
            }

            var props = new AuthenticationProperties(new Dictionary<string, string>
            {
                {
                    "audience", clientId
                }
            });

            var ticket = new AuthenticationTicket(identity, props);
            return ticket;
        }

        public static short GetTokenExpirationMinutes()
        {
            return Int16.Parse(WebConfigurationManager.AppSettings["TokenExpirationMinutes"]);
        }

        public static string GetFacebookAppToken()
        {
            return WebConfigurationManager.AppSettings["FacebookAppToken"];
        }
    }

    public static class TaskExtensions
    {
        public static readonly Task CompletedTask = Task.FromResult(false);
    }
}