using AuthorizationServer.Api.Formats;
using AuthorizationServer.Api.Providers;
using Microsoft.Owin;
using Microsoft.Owin.Security.OAuth;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.Jwt;
using Owin;
using System;
using System.Threading.Tasks;
using System.Web.Configuration;
using System.Web.Http;
using AuthenticationMode = Microsoft.Owin.Security.AuthenticationMode;

namespace AuthorizationServer.Api
{
    public class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            HttpConfiguration config = new HttpConfiguration();

            // Web API routes
            config.MapHttpAttributeRoutes();
            
            ConfigureOAuth(app);
            ConfigureOAuthValidation(app);

            app.UseCors(Microsoft.Owin.Cors.CorsOptions.AllowAll);
            
            app.UseWebApi(config);

        }

        public void ConfigureOAuthValidation(IAppBuilder app)
        {
            var issuer = "http://jwtauthzsrv.azurewebsites.net";
            var audience = "099153c2625149bc8ecb3e85e03f0022";
            var secret = TextEncodings.Base64Url.Decode("IxrAjDoa2FqElO7IhrSrUJELhUckePEPVpaePlS_Xaw");

            var jwtBearerAuthenticationOptions = new JwtBearerAuthenticationOptions
            {
                AuthenticationMode = AuthenticationMode.Active,
                AllowedAudiences = new[] {audience},
                IssuerSecurityTokenProviders = new IIssuerSecurityTokenProvider[]
                {
                    new SymmetricKeyIssuerSecurityTokenProvider(issuer, secret)
                },
                Provider = new OAuthBearerAuthenticationProvider
                {
                    OnValidateIdentity = context =>
                    {
                        context.Ticket.Identity.AddClaim(new System.Security.Claims.Claim("newCustomClaim", "newValue"));
                        return Task.FromResult<object>(null);
                    }
                }
            };

            // Api controllers with an [Authorize] attribute will be validated with JWT
            app.UseJwtBearerAuthentication(jwtBearerAuthenticationOptions);

        }

        public void ConfigureOAuth(IAppBuilder app)
        {
            //OAuthBearerOptions = new OAuthBearerAuthenticationOptions();

            var tokenExpirationMinutes = Helper.GetTokenExpirationMinutes();

            OAuthAuthorizationServerOptions OAuthServerOptions = new OAuthAuthorizationServerOptions()
            {
                //For Dev enviroment only (on production should be AllowInsecureHttp = false)
                AllowInsecureHttp = true,
                TokenEndpointPath = new PathString("/oauth2/token"),
                AccessTokenExpireTimeSpan = TimeSpan.FromMinutes(tokenExpirationMinutes),
                Provider = new CustomOAuthProvider(),
                RefreshTokenProvider = new SimpleRefreshTokenProvider(),
                AccessTokenFormat = new CustomJwtFormat(WebConfigurationManager.AppSettings["TokenIssuer"])
            };

            // OAuth 2.0 Bearer Access Token Generation
            app.UseOAuthAuthorizationServer(OAuthServerOptions);
            //app.UseOAuthBearerAuthentication(OAuthBearerOptions);
        }
    }
}