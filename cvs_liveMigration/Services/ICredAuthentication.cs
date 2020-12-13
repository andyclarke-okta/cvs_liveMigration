using okta_aspnetcore_mvc_example.Models;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace okta_aspnetcore_mvc_example.Services
{
    public interface ICredAuthentication
    {

        bool CheckCredentialServer(LdapServiceModel ldapServiceModel);
        //bool IsAuthenticated(string username, string password);

        bool IsAuthenticated(string username, string password, LdapServiceModel ldapServiceModel);
        CustomUser IsCreated(string username, string password, LdapServiceModel ldapServiceModel);


    }
}
