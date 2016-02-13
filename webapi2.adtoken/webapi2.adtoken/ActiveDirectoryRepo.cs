using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Linq;
using System.Net;
using System.Threading.Tasks;
using System.Web;

namespace webapi2.adtoken
{
    public class ActiveDirectoryRepo : IActiveDirectoryRepo, IDisposable
    {
        public ActiveDirectoryRepo()
        {

        }

        /// <summary>
        /// This method is responsible for validating user credentials
        /// against LDAP server
        /// </summary>
        /// <param name="domain"> domain against which we validate credentials</param>
        /// <param name="usr"> user name</param>
        /// <param name="pwd"> password for the user</param>
        /// <returns></returns>
        public Task<bool> ValidateADcredentialsAsync(string domain, string usr, string pwd)
        {
            return Task.Factory.StartNew(() =>
            {
                try
                {
                    LdapConnection connection = new LdapConnection(domain);
                    NetworkCredential credential = new NetworkCredential(usr, pwd);
                    connection.Credential = credential;
                    connection.Bind();

                    return true;
                }
                catch (LdapException lexc)
                {
                    String error = lexc.ServerErrorMessage;
                    return false;
                }
                catch (Exception exc)
                {
                    return false;
                }
            });
        }

        public Task<List<string>> GetUserGroupsAsync(string LDAPdomain, string username, string groupNamePrefix)
        {
            return (Task<List<string>>) Task.Factory.StartNew(() =>
            {
               try
               {
                  DirectoryEntry de = null;
                  DirectorySearcher directorySearcher = null;

                  //TODO: AD user needs to be from config!
                  de = new DirectoryEntry("LDAP://" + "<DOMAIN-NAME>, "<LDAP-bind-username>", "<LDAP-bind-password");
                  directorySearcher = new DirectorySearcher(de);
                  directorySearcher.PropertiesToLoad.Add("memberOf");
                  directorySearcher.Filter = $"(&(objectClass=person)(objectCategory=user)(sAMAccountname={username}))";
                  SearchResult searchResult = directorySearcher.FindOne();

                  var singleResult = searchResult.GetDirectoryEntry();

                  List<string> memberof = new List<string>();

                  var memberOfs = singleResult.Properties["memberOf"];

                  foreach (object oMember in memberOfs)
                  {
                      try
                      {

                          // Here we call Regex.Match.
                          Match match = Regex.Match(oMember.ToString(), @"CN=([^,]+),", RegexOptions.IgnoreCase);

                          // Here we check the Match instance.
                          if (match.Success)
                          {

                              memberof.Add(match.Groups[1].Value);

                          }


                      }
                      catch
                      {
                      }
                  }
                  // This could be done already before so we skipp unnecessary adds
                  return memberof.Where(r => r.Contains(groupNamePrefix)).ToList();
                }


                catch (Exception exc)
                {
                    return null;
                }
            }
          );
        }

        public void Dispose()
        {

        }
    }

    /// <summary>
    /// Interface used to describe actions executed against AD
    /// </summary>
    public interface IActiveDirectoryRepo
    {
        Task<bool>          ValidateADcredentialsAsync(string domain, string usr, string pwd);
        Task<List<string>>  GetUserGroupsAsync(string LDAPdomain, string username, string groupNamePrefix);

    }
}
