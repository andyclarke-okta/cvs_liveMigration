using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

using System.Collections.Specialized;
using System.Configuration;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using okta_aspnetcore_mvc_example.Models;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using System.Net;

namespace okta_aspnetcore_mvc_example.Services
{
    public class LdapAuthentication : ICredAuthentication
    {
        private readonly ILogger<LdapAuthentication> _logger;
        private readonly IConfiguration _config;

        // LDAP settings
        private string _ldapServer = null;
        private string _ldapPort = null;
        private string _baseDn = null;

        private const int LDAPError_InvalidCredentials = 0x31;
        private string _ldapPath = null;

        public LdapAuthentication(ILogger<LdapAuthentication> logger, IConfiguration config )
        {
            _logger = logger;
            _config = config;

        }

        public bool CheckCredentialServer(LdapServiceModel ldapServiceModel)
        {
            bool success = false;
            _ldapServer = ldapServiceModel.ldapServer;
            _ldapPort = ldapServiceModel.ldapPort;
            LdapDirectoryIdentifier ldapDirectoryIdentifier = new LdapDirectoryIdentifier(_ldapServer, Convert.ToInt16(_ldapPort), true, false);
            LdapConnection ldapConnection = new LdapConnection(ldapDirectoryIdentifier);

            try
            {
                ldapConnection.AuthType = AuthType.Anonymous;
                ldapConnection.AutoBind = false;
                ldapConnection.Timeout = new TimeSpan(0, 0, 0, 1);
                ldapConnection.Bind();
                ldapConnection.Dispose();
                success = true;
            }
            catch (LdapException)
            {
                success = false;
            }

            return success;
        }


        public bool IsAuthenticated(string username, string password, LdapServiceModel ldapServiceModel)
        {
            _ldapServer = ldapServiceModel.ldapServer;
            _ldapPort = ldapServiceModel.ldapPort;
            _baseDn = ldapServiceModel.baseDn;

            _ldapPath = string.Format("LDAP://{0}:{1}", _ldapServer, _ldapPort);

            bool success = false;
            //username must be user full domain name. build UID string
            string modUsername = "cn=" + username + _baseDn;


            try
            {
                LdapDirectoryIdentifier ldapDirectoryIdentifier = new LdapDirectoryIdentifier(_ldapServer, Convert.ToInt16(_ldapPort), true, false);
                LdapConnection ldapConnection = new LdapConnection(ldapDirectoryIdentifier);
                ldapConnection.SessionOptions.ProtocolVersion = 3;
                ldapConnection.AuthType = AuthType.Basic;
 
                ldapConnection.Timeout = new TimeSpan(0, 0, 10);
                ldapConnection.Credential = new NetworkCredential(modUsername, password);
                ldapConnection.Bind();

                //if bind does not cause error then it is successful
                ldapConnection.Dispose();
                //_logger.Debug("ldap successfully validated username " + username);
                success = true;
            }
            catch (LdapException ldapException)
            {
                //add additional error handling
                if (ldapException.ErrorCode.Equals(LDAPError_InvalidCredentials))
                { success = false; }

                success = false;
            }
            catch (Exception ex)
            {
                //add additional error handling
                success = false;
            }

            return success;
        }



        public CustomUser IsCreated(string username, string password, LdapServiceModel ldapServiceModel)
        {
            _ldapServer = ldapServiceModel.ldapServer;
            _ldapPort = ldapServiceModel.ldapPort;
            _baseDn = ldapServiceModel.baseDn;

            bool success = false;
            CustomUser customUser = null;

            //username must be user full domain name. build UID string
            string modUsername = "cn=" + username + _baseDn;
            //string tempPath = "LDAP://34.225.255.214:389/cn=ntalarico,ou=People,dc=talarico,dc=com";
            //_ldapPath = string.Format("LDAP://{0}:{1}", _ldapServer, _ldapPort);
            _ldapPath = string.Format("LDAP://{0}:{1}/{2}", _ldapServer, _ldapPort, modUsername);

            DirectoryEntry entry = new DirectoryEntry(_ldapPath, modUsername, password);
            //DirectoryEntry entry = new DirectoryEntry(tempPath, modUsername, password);
            entry.AuthenticationType = AuthenticationTypes.None;

            try
            {
                // Bind to the native AdsObject to force authentication.
                // if no exception, then login successful
                Object connected = entry.NativeObject;
                DirectorySearcher directorySearcher = new DirectorySearcher(entry);
                //directorySearcher.Filter = "(cn=" + username + ")";
                SearchResult result = null;
                try
                {
                     result = directorySearcher.FindOne();
                }
                catch (Exception ex)
                {
                    var test = ex.Message.ToString();
                    
                }
                
                if (result != null)
                {

                    //User oktaUser = new User();
                    customUser = new CustomUser();

                    string path = result.Path;
                    customUser.LastName = (String)result.Properties["sn"][0];
                    customUser.FirstName = (String)result.Properties["givenname"][0];
                    customUser.Email = (String)result.Properties["mail"][0];

                    success = true;
                }


            }
            catch (LdapException ldapException)
            {
                //add additional error handling
                if (ldapException.ErrorCode.Equals(LDAPError_InvalidCredentials))
                { success = false; }

                success = false;
            }
            catch (Exception ex)
            {
                //add additional error handling
                success = false;
            }

            return customUser;
        }


    }
}
