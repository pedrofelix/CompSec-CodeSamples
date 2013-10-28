using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Web;
using System.Web.Mvc;

namespace RelyingParty2.Controllers
{
    public class HomeController : Controller
    {
        public string Index()
        {
            var princ = User as ClaimsPrincipal;
            var sb = new StringBuilder();
            sb.Append("<html><body><ul>");
            foreach (var claim in princ.Claims)
            {
                sb.Append(string.Format("<li>{0} - {1}</li>", claim.Type, claim.Value));
            }
            sb.Append("</ul></body></html>");
            return sb.ToString();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }
    }
}