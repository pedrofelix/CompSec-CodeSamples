using System;
using System.Collections.Generic;
using System.IdentityModel;
using System.IdentityModel.Configuration;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Services;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography.X509Certificates;
using System.Web;
using System.Web.Mvc;

namespace IdentityProvider.Controllers
{
    public class WsFedController : Controller
    {
        public void SignIn()
        {
            var req = WSFederationMessage.CreateFromUri(Request.Url);

            try
            {

                var resp = FederatedPassiveSecurityTokenServiceOperations.ProcessSignInRequest(
                    req as SignInRequestMessage,
                    new ClaimsPrincipal(new ClaimsIdentity(new[]
                    {
                        new Claim(ClaimTypes.NameIdentifier, "Alice"),
                        new Claim(ClaimTypes.Email, "alice@wonder.land"),
                        new Claim("http://example.com/claims/course_enrollment", "Computer Security"),
                        new Claim("http://example.com/claims/course_enrollment", "Concurrent Programming")
                    }, "wsfed")),
                    new LectureSecurityTokenService(new LectureSecurityTokenServiceConfiguration()));
                    resp.Write(Response.Output);
                    
            }
            catch (InvalidOperationException e)
            {
                Response.StatusCode = 400;
                Response.Write(e.Message);
            }
            Response.End();
        }
	}

    public class LectureSecurityTokenService : SecurityTokenService
    {
        public LectureSecurityTokenService(SecurityTokenServiceConfiguration securityTokenServiceConfiguration) : base(securityTokenServiceConfiguration)
        {
        }

        protected override Scope GetScope(ClaimsPrincipal principal, RequestSecurityToken request)
        {
            if (request.AppliesTo == null || request.AppliesTo.Uri == null)
            {
                throw new InvalidRequestException("AppliesTo must be defined");
            }
            if (request.AppliesTo.Uri.ToString() != "https://www.example.net/")
            {
                throw new InvalidOperationException("Go away, I do not know you!");
            }
            var scope = new Scope(
                request.AppliesTo.Uri.AbsoluteUri,
                SecurityTokenServiceConfiguration.SigningCredentials
                )
            {
                ReplyToAddress = request.AppliesTo.Uri.AbsoluteUri,
                TokenEncryptionRequired = false
            };
            return scope;
        }

        protected override ClaimsIdentity GetOutputClaimsIdentity(
            ClaimsPrincipal principal, 
            RequestSecurityToken request, 
            Scope scope)
        {
            var ident = principal.Identities.FirstOrDefault();
            if (ident == null)
            {
                throw new InvalidRequestException("Requestor must have at least one claims identity");
            }
            return ident;
        }
    }

    public class LectureSecurityTokenServiceConfiguration : SecurityTokenServiceConfiguration
    {
        public LectureSecurityTokenServiceConfiguration()
        {
            this.SecurityTokenService = typeof(LectureSecurityTokenService);
            var cert = X509StoreExt.GetCertificateFromStoreBySubjectName(
                StoreName.My, 
                StoreLocation.LocalMachine,
                "idp.example.org");
            this.SigningCredentials = new X509SigningCredentials(cert);
            this.TokenIssuerName = "https://idp.example.org";
        }
    }

    public class X509StoreExt
    {
        public static R Use<R>(StoreName name, StoreLocation loc, Func<X509Store, R> f)
        {
            var store = new X509Store(name, loc);
            try
            {
                store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly | OpenFlags.IncludeArchived);
                return f(store);
            }
            finally
            {
                store.Close();
            }
        }

        public static X509Certificate2 GetCertificateFromStoreBySubjectName(StoreName name, StoreLocation loc, string subject)
        {
            return X509StoreExt.Use(name, loc, s =>
            {
                var coll = s.Certificates.Find(X509FindType.FindBySubjectName, subject,
                                    false);
                return coll.Count > 0 ? coll[0] : null;
            });
        }
    }
}