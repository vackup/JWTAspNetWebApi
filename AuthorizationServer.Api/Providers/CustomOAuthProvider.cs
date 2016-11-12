using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace AuthorizationServer.Api.Providers
{
    public class CustomOAuthProvider : OAuthAuthorizationServerProvider
    {

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId = string.Empty;
            string clientSecret = string.Empty;
            string symmetricKeyAsBase64 = string.Empty;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (context.ClientId == null)
            {
                context.SetError("invalid_clientId", "client_Id is not set");
                return Task.FromResult<object>(null);
            }

            // TODO: crete AudiencesStore to database and mix with client entity and validation with AngularJSAuthentication.SimpleAuthorizationServerProvider
            var audience = AudiencesStore.FindAudience(context.ClientId);

            if (audience == null)
            {
                context.SetError("invalid_clientId", string.Format("Invalid client_id '{0}'", context.ClientId));
                return Task.FromResult<object>(null);
            }

            //using (AuthRepository _repo = new AuthRepository())
            //{
            //    client = _repo.FindClient(context.ClientId);
            //}

            //if (client == null)
            //{
            //    context.SetError("invalid_clientId", string.Format("Client '{0}' is not registered in the system.", context.ClientId));
            //    return Task.FromResult<object>(null);
            //}

            //if (client.ApplicationType == Models.ApplicationTypes.NativeConfidential)
            //{
            //    if (string.IsNullOrWhiteSpace(clientSecret))
            //    {
            //        context.SetError("invalid_clientId", "Client secret should be sent.");
            //        return Task.FromResult<object>(null);
            //    }
            //    else
            //    {
            //        if (client.Secret != Helper.GetHash(clientSecret))
            //        {
            //            context.SetError("invalid_clientId", "Client secret is invalid.");
            //            return Task.FromResult<object>(null);
            //        }
            //    }
            //}

            //if (!client.Active)
            //{
            //    context.SetError("invalid_clientId", "Client is inactive.");
            //    return Task.FromResult<object>(null);
            //}

            //context.OwinContext.Set<string>("as:clientAllowedOrigin", client.AllowedOrigin);
            //context.OwinContext.Set<string>("as:clientRefreshTokenLifeTime", client.RefreshTokenLifeTime.ToString());

            context.Validated();
            return Task.FromResult<object>(null);
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            var repo = new AuthRepository();

            var user = await repo.FindUser(context.UserName, context.Password);

            if (user == null)
            {
                context.SetError("invalid_grant", "The user name or password is incorrect");
                //return;
                return;
            }

            var userName = context.UserName;
            var clientId = context.ClientId ?? string.Empty;

            // TODO: get roles from database
            var roleList = new List<string> { "Manager", "Supervisor" };

            var ticket = Helper.GetJwtAuthenticationTicket(userName, roleList, clientId);
            context.Validated(ticket);
            return;
        }

        

        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["audience"];
            var currentClient = context.ClientId;

            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }

            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);

            var newClaim = newIdentity.Claims.Where(c => c.Type == "newClaim").FirstOrDefault();
            if (newClaim != null)
            {
                newIdentity.RemoveClaim(newClaim);
            }
            newIdentity.AddClaim(new Claim("newClaim", "newValue"));

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }
    }
}