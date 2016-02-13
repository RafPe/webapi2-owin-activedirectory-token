using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security.OAuth;

namespace webapi2.adtoken
{

  public class ADAuthorizationServerProvider : OAuthAuthorizationServerProvider
  {
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
                  var usercredentialsAreValid = await _repo.ValidateADcredentialsAsync("<DOMAIN-NAME>", clientId, clientSecret);

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

          var identity = new ClaimsIdentity(context.Options.AuthenticationType);

          identity.AddClaim(new Claim(ClaimTypes.Name, context.ClientId));

          using (ActiveDirectoryRepo _repo = new ActiveDirectoryRepo())
          {
              var groups = await _repo.GetUserGroupsAsync("<DOMAIN-NAME>", context.ClientId, "<GROUP-PREFIX>");

              //identity.AddClaim(new Claim("sub", context.UserName));
              foreach (string name in groups)
              {
                  identity.AddClaim(new Claim("role", name));
              }

              if (context.ClientId == null)
              {
                  context.SetError("invalid_grant", "Supplied credentials are not valid");
                  return;
              }
          }

          context.Validated(identity);

      }
  }


}
