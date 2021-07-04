
using Common;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Newtonsoft.Json;
using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading.Tasks;

namespace Client.Controllers
{
    public class HomeController : Controller
    {
        public HttpClient Client { get; }
        private readonly IHttpClientFactory _clientFactory;
        public HomeController(IHttpClientFactory clientFactory)
        {
            _clientFactory = clientFactory;
            var client = _clientFactory.CreateClient();
            client.BaseAddress = new Uri("https://localhost:5001/");
            // GitHub API versioning
            client.DefaultRequestHeaders.Add("Accept",
                "application/json");
            // GitHub requires a user-agent
            client.DefaultRequestHeaders.Add("User-Agent",
                "HttpClientFactory-Sample");

            Client = client;
        }
            
        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public async Task<IActionResult> Privacy()
        {


          
            string accessToken = await HttpContext.GetTokenAsync("access_token");
            string refreshToken = await HttpContext.GetTokenAsync("refresh_token");
            string idtoken = await HttpContext.GetTokenAsync("id_token");
            Client.DefaultRequestHeaders.Authorization
                         = new AuthenticationHeaderValue("Bearer", accessToken);
            

                        var sendmessage = new EmailData { toAddress = "gvreddy0209@gmail.com", message = "test", subject = "your wpd rest link" };
            var myContent = JsonConvert.SerializeObject(sendmessage);
            var buffer = System.Text.Encoding.UTF8.GetBytes(myContent);
            var byteContent = new ByteArrayContent(buffer);
            byteContent.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");
            var result=await Client.PostAsync("/myAPI", byteContent);
            ViewBag.Message = "Password  sent to your email address!";
   

            return Content($"Current user: <span id=\"UserIdentityName\">{User.Identity.Name ?? "anonymous"}</span><br/>" +
         $"<div>Access token: {accessToken}</div><br/>" +
          $"<div>ID token: {idtoken}</div><br/>" +
         $"<div>Refresh token: {refreshToken}</div><br/>"
         , "text/html");

            return View();
        }


      
    }
}
