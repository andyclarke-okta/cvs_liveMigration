using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Cors;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Okta.Sdk;
using Okta.Sdk.Configuration;
using okta_aspnetcore_mvc_example.Models;
using okta_aspnetcore_mvc_example.Services;

namespace okta_aspnetcore_mvc_example.Controllers
{

    public class MigrationController : ControllerBase
    {

        private readonly ILogger<MigrationController> _logger;
        private readonly IConfiguration _config;
        public LdapServiceModel _ldapServiceModel = null;
        private ICredAuthentication _credAuthentication = null;

        public MigrationController(ILogger<MigrationController> logger, IConfiguration config, ICredAuthentication ldap)
        {
            _logger = logger;
            _config = config;
            _credAuthentication = ldap; //the service is injected by the GL app, the parameters are passed in on the method call

            _ldapServiceModel = new LdapServiceModel();
            _ldapServiceModel.ldapServer = _config.GetValue<string>("ldapSettings:ldapServer");
            _ldapServiceModel.ldapPort = _config.GetValue<string>("ldapSettings:ldapPort");
            _ldapServiceModel.baseDn = _config.GetValue<string>("ldapSettings:baseDn");

        }

        [HttpPost]
        [Route("api/ValidateUser")]
        public IActionResult ValidateUser(string psw,string username )
        {
            string temp = psw;
            PswMigrationResponse pswMigrationRsp = new PswMigrationResponse();

            Okta.Sdk.IUser oktaUser = null;

            var client = new OktaClient(new OktaClientConfiguration
            {
                OktaDomain = _config.GetValue<string>("OktaWeb:OktaDomain"),
                Token = _config.GetValue<string>("OktaWeb:ApiToken")
            });

            //use received username and password to bind with LDAP
            //if password is valid, set password in Okta
            try
            {
                //check username in Okta and password status
                oktaUser = (Okta.Sdk.User)client.Users.GetUserAsync(username).Result;
            }
            catch (OktaApiException ex)
            {
          
                //trap error, handle User is null
                var test = ex.ErrorCode;
            }
            catch (Exception e)
            {
                //trap error, handle User is null
                OktaApiException myExp = (OktaApiException)e.InnerException;
                var myErr = myExp.ErrorCode;
                
            }

            if (oktaUser != null)
            {
                //if user password already set, no furhter processing
                if (oktaUser.Profile["IsPasswordInOkta"] == null || oktaUser.Profile["IsPasswordInOkta"].ToString() == "false")
                {
                    //check user credentials in LDAP
                    bool rspIsAuthenticated = _credAuthentication.IsAuthenticated(username, psw, _ldapServiceModel);

                    if (rspIsAuthenticated)
                    {
                        //set password in Okta
                        Okta.Sdk.PasswordCredential setPassword = new Okta.Sdk.PasswordCredential();
                        setPassword.Value = psw;

                        oktaUser.Credentials.Password = setPassword;
                        oktaUser.Profile["IsPasswordInOkta"] = "true";

                        Okta.Sdk.IUser rspPartialUpdate = oktaUser.UpdateAsync().Result;

                        if (rspPartialUpdate != null)
                        {

                            if (rspPartialUpdate.PasswordChanged != null)
                            {
                                pswMigrationRsp.status = "set password in Okta successful";
                                pswMigrationRsp.isPasswordInOkta = "true";
                            }
                            else
                            {
                                pswMigrationRsp.status = "set password in Okta failed";
                                pswMigrationRsp.isPasswordInOkta = "false";
                            }
                        }
                        else
                        {
                            pswMigrationRsp.status = "set password in Okta failed";
                            pswMigrationRsp.isPasswordInOkta = "false";
                        }
                    }
                    else
                    {
                        //arrive here is user creds not validated in Ldap
                        pswMigrationRsp.status = "LDAP validation failed";
                        pswMigrationRsp.isPasswordInOkta = "false";
                    }

                }
                else
                {
                    //no work required
                    pswMigrationRsp.status = oktaUser.Status;
                    pswMigrationRsp.isPasswordInOkta = "true";
                }
                //build response
                pswMigrationRsp.oktaId = oktaUser.Id;
                pswMigrationRsp.login = oktaUser.Profile.Login;

            }
            else
            {
                //arrive here if user not found in Okta
                //check user credentials and get profile from LDAP
                //Okta.Sdk.IUser rspOktaUser = null;
                CustomUser rspCustomUser = _credAuthentication.IsCreated(username, psw, _ldapServiceModel);
                if (rspCustomUser != null)
                {
                    //create Okta user with password
                    //dont auto activate, sincewe dont want email
                    CreateUserWithPasswordOptions newUserOptions = new CreateUserWithPasswordOptions
                    {
                        // User profile object
                        Profile = new UserProfile
                        {
                            Login = rspCustomUser.Email,
                            FirstName = rspCustomUser.FirstName,
                            LastName = rspCustomUser.LastName,
                            Email = rspCustomUser.Email
                        },
                        Password = psw,
                        Activate = false,
                    };
                    newUserOptions.Profile["IsPasswordInOkta"] = "true";
                    Okta.Sdk.IUser rspAddCustomUser = client.Users.CreateUserAsync(newUserOptions).Result;


                    if (rspAddCustomUser != null)
                    {

                        var rspActivate  = rspAddCustomUser.ActivateAsync(sendEmail: false).Result;
                        if (rspActivate != null)
                        {

                            pswMigrationRsp.oktaId = rspAddCustomUser.Id;
                            pswMigrationRsp.login = rspAddCustomUser.Profile.Login;
                            pswMigrationRsp.status = "Created in Okta";
                            pswMigrationRsp.isPasswordInOkta = "true";


                        }
                        else
                        {
                            pswMigrationRsp.oktaId = rspAddCustomUser.Id;
                            pswMigrationRsp.login = rspAddCustomUser.Profile.Login;
                            pswMigrationRsp.status = "User NOT ACTIVE in Okta";
                            pswMigrationRsp.isPasswordInOkta = "unknown";
                        }
                    }
                    else
                    {
                        pswMigrationRsp.oktaId = "none";
                        pswMigrationRsp.login = "none";
                        pswMigrationRsp.status = "User NOT Created in Okta";
                        pswMigrationRsp.isPasswordInOkta = "false";
                    }

                }
                else
                {
                    pswMigrationRsp.oktaId = "none";
                    pswMigrationRsp.login = "none";
                    pswMigrationRsp.status = "User NOT found in External Source";
                    pswMigrationRsp.isPasswordInOkta = "false";
                }


            }

            return Content(content: JsonConvert.SerializeObject(pswMigrationRsp), contentType: "application/json");


            // return this.Ok("Web Api unprotected endpoint, SUCCESS");
        }




    }
}
