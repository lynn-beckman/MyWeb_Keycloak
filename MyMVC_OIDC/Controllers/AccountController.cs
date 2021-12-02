using Microsoft.AspNetCore.Mvc;

namespace MyMVC_OIDC.Controllers
{
    public class AccountController : Controller
    {
        public IActionResult AccessDenied()
        {
            return View();
        }
    }
}
