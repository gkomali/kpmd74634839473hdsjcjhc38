using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Common;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace API.Controllers
{
    
    [ApiController]
    [Route("myAPI")]
    public class WeatherForecastController : ControllerBase
    {
        [Authorize]
        [HttpPost]
        public async Task<bool> Post(EmailData emailData)
        {
            //good 
            return true;
        }

      

        [HttpGet]
        public string Get()
        {
            

            return "I am your API ready for you";
        }
    }
}
