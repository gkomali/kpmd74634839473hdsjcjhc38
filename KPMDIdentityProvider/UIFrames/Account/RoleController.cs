using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityProvider.Quickstart.Account
{
   
        public class RoleController : Controller
        {
        private readonly RoleManager<IdentityRole> roleManager;
        private readonly UserManager<IdentityUser> userManager;
        public RoleController(RoleManager<IdentityRole> roleManager,UserManager<IdentityUser> userManager)
            {
                this.roleManager = roleManager;
            this.userManager = userManager;
        }

            public IActionResult Index()
            {
                var roles = roleManager.Roles.ToList();
                return View(roles);
            }

            public IActionResult Create()
            {
                return View(new IdentityRole());
            }

            [HttpPost]
            public async Task<IActionResult> Create(IdentityRole role)
            {
                await roleManager.CreateAsync(role);
                return RedirectToAction("Index");
            }


        //make a display for manage
        [HttpGet]
        public async Task<IActionResult> EditUsersInRole(RoleData iRole)
        {
            var role = await roleManager.FindByIdAsync(iRole.Id);

            if (role == null)
            {
                ViewBag.ErrorMessage = $"Role with Id = {iRole.Id} cannot be found";
                return View("NotFound");
            }
            var model = new List<UserRoleViewModel>();

            foreach (var user in userManager.Users)
            {
                var userRoleViewModel = new UserRoleViewModel
                {
                    UserId = user.Id,
                    UserName = user.UserName,
                    Sugggestedrole=iRole.Id
                };

                if (await userManager.IsInRoleAsync(user, role.Name))
                {
                    userRoleViewModel.IsSelected = true;
                }
                else
                {
                    userRoleViewModel.IsSelected = false;
                }

                model.Add(userRoleViewModel);
            }

            
            return View(model);
        }
        //fix mange reqeust and return to previos view
        [HttpPost]
        public async Task<IActionResult> EditUsersInRole(List<UserRoleViewModel> model)
        {
            var roleId = model.Find(x => x.Sugggestedrole != null).Sugggestedrole;
            var role = await roleManager.FindByIdAsync(roleId);

            if (role == null)
            {
                ViewBag.ErrorMessage = $"Role with Id = {roleId} cannot be found";
                return View("NotFound");
            }

            for (int i = 0; i < model.Count; i++)
            {
                var user = await userManager.FindByIdAsync(model[i].UserId);

                IdentityResult result = null;

                if (model[i].IsSelected && !(await userManager.IsInRoleAsync(user, role.Name)))
                {
                    result = await userManager.AddToRoleAsync(user, role.Name);
                }
                else if (!model[i].IsSelected && await userManager.IsInRoleAsync(user, role.Name))
                {
                    result = await userManager.RemoveFromRoleAsync(user, role.Name);
                }
                else
                {
                    continue;
                }

                if (result.Succeeded)
                {
                    if (i < (model.Count - 1))
                        continue;
                    else
                        return RedirectToAction("Index");
                }
            }

            return RedirectToAction("Index");
        }


        [HttpPost]
        public async Task<IActionResult> Delete(RoleData iRole)
        {
            var role = await roleManager.FindByIdAsync(iRole.Id);

            if (role == null)
            {
                ViewBag.ErrorMessage = $"Role with Id = {iRole.Id} cannot be found";
                return View("NotFound");
            }
            await roleManager.DeleteAsync(role);
            return RedirectToAction("Index");
        }
    }
    public class RoleData
    {
        public string Id { get; set; }
        public string Name { get; set; }
        public string subject { get; set; }

    }
}


