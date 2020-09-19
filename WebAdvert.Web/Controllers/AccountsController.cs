using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Security.Policy;
using System.Threading.Tasks;
using Amazon.AspNetCore.Identity.Cognito;
using Amazon.Extensions.CognitoAuthentication;
using Amazon.Runtime.Internal.Transform;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAdvert.Web.Models.Accounts;

namespace WebAdvert.Web.Controllers
{
    public class AccountsController : Controller
    {
        private readonly SignInManager<CognitoUser> _signInManager;
        private readonly UserManager<CognitoUser> _userManager;
        private readonly CognitoUserPool _pool;

        public AccountsController(SignInManager<CognitoUser> signInManager, UserManager<CognitoUser> userManager, CognitoUserPool pool)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _pool = pool;
        }
        public async Task<IActionResult> SignUp()
        {
            var model = new SignupModel();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> SignUp(SignupModel model)
        {
            if (ModelState.IsValid)
            {
                var userFound = await _userManager.FindByEmailAsync(model.Email);
                if (userFound != null)
                {
                    ModelState.AddModelError("UserExists", "User already exists");
                    return View(model);
                }
                var user = _pool.GetUser(model.Email);
                user.Attributes.Add(CognitoAttribute.Name.ToString(), model.Email);
                var createdUser = await _userManager.CreateAsync(user, model.Password);

                if (createdUser.Succeeded)
                {
                    return RedirectToAction("Confirm");
                }
                //User creation still fails so show some errors
                foreach(var error in createdUser.Errors)
                {
                    ModelState.AddModelError(error.Code, error.Description);
                }
                
            }
            return View(model);
        }
        public async Task<IActionResult> Confirm(ConfirmModel model)
        {
            return View(model);
        }
        [HttpPost]
        public async Task<IActionResult> Confirm_Post(ConfirmModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);

                if (User == null)
                {
                    ModelState.AddModelError("NoteFound", "A user was not found with this email address");
                    return View(model);
                }

                var result = await (_userManager as CognitoUserManager<CognitoUser>).ConfirmSignUpAsync(user, model.Code, true);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    foreach (var item in result.Errors)
                    {
                        ModelState.AddModelError(item.Code, item.Description);
                    }
                    return View(model);
                }
            }
            return View(model);
        }
        [HttpGet]
        public async Task<IActionResult> Login()
        {
            var model = new LoginModel();
            return View(model);
        }

        [HttpPost]
        [ActionName("Login")]
        public async Task<IActionResult> Login_Post(LoginModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);
                if (result.Succeeded)
                {
                    return RedirectToAction("Index", "Home");
                }
                else
                {
                    ModelState.AddModelError("LoginError", "Email and password do not match");
                }
            }
            return View("Login", model);
        }
        [HttpGet]
        public async Task<IActionResult> ForgotPassword()
        {
            var model = new ForgotPasswordModel();
            return View(model);
        }

        [HttpPost]
        [ActionName("ForgotPassword")]
        public async Task<IActionResult> ForgotPassword_Post(ForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null) return View("Login", new LoginModel { Email = model.Email });

                await user.ForgotPasswordAsync();

                return View("ConfirmForgotPassword", new ConfirmForgotPasswordModel() {Email = model.Email});
            }
            return View("Login", model);
        }
        [HttpGet]
        public async Task<IActionResult> ConfirmForgotPassword(ConfirmForgotPasswordModel model)
        {
            return View(model);
        }

        [HttpPost]
        [ActionName("ConfirmForgotPassword")]
        public async Task<IActionResult> ConfirmForgotPassword_Post(ConfirmForgotPasswordModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                
                if (user == null) return View("Login", new LoginModel { Email = model.Email });

                await user.ConfirmForgotPasswordAsync(model.Code, model.Password);
                return View("ForgotPasswordConfirmed");
            }
            return View("Login", model);
        }
        [HttpGet]
        public async Task<IActionResult> ForgotPasswordConfirmed()
        {
            return View();
        }
    }
}
