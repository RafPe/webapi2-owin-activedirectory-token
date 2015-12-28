using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.OAuth;

namespace webapi2.adtoken
{
    public class ADAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        /// <summary>
        /// In this methods we validate our client credentials
        /// </summary>
        /// <param name="context"></param>
        /// <returns></returns>
        public override async Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {
            string clientId = string.Empty;
            string clientSecret = string.Empty;

            if (!context.TryGetBasicCredentials(out clientId, out clientSecret))
            {
                context.TryGetFormCredentials(out clientId, out clientSecret);
            }

            if (clientId == null && clientSecret == null)
            {
                   context.Rejected();
                   context.SetError("invalid_client", "Client credentials could not be retrieved");

                   return;
            }
            else
            {

                using (ActiveDirectoryRepo _repo = new ActiveDirectoryRepo())
                {
                    //TODO 5: TO BE CHANGED WITH VARIABLES FROM CONTEXT
                    var usercredentialsAreValid = await _repo.ValidateADcredentialsAsync("", "", "");

                    if (!usercredentialsAreValid)
                    {
                        context.Rejected();
                        context.SetError("invalid_grant", "The user name or password is incorrect.");

                        return;
                    }
                    else
                    {
                        context.Validated();
                    }
                }

                
            }

            


            
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { "*" });

            using (ActiveDirectoryRepo _repo = new ActiveDirectoryRepo())
            {
                //TODO 4: TO BE CHANGED WITH VARIABLES FROM CONTEXT
                var user = await _repo.GetUserGroupsAsync("","","");

                if (context.UserName == null)
                {
                    context.SetError("invalid_grant", "The user name or password is incorrect.");
                    return;
                }
            }

            var identity = new ClaimsIdentity(context.Options.AuthenticationType);

            //TODO  2: THIS SHOULD BE DYNAMIC FROM AD GROUPS ? DEPENDING ON USER NEEDS
            identity.AddClaim(new Claim(ClaimTypes.Name, context.UserName));

            identity.AddClaim(new Claim("sub", context.UserName));
            identity.AddClaim(new Claim("role", "user"));

            context.Validated(identity);

        }
    }
}
}