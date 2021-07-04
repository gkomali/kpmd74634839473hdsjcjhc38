using MailKit.Net.Smtp;
using MailKit.Security;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using MimeKit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace KPMDCommunciations.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class WeatherForecastController : ControllerBase
    {
        private static readonly string[] Summaries = new[]
        {
            "Freezing", "Bracing", "Chilly", "Cool", "Mild", "Warm", "Balmy", "Hot", "Sweltering", "Scorching"
        };

        private readonly ILogger<WeatherForecastController> _logger;
        private readonly MailSettings _mailSettings;

        public WeatherForecastController(ILogger<WeatherForecastController> logger, IOptions<MailSettings> appSettings)
        {
            _logger = logger;
            _mailSettings = appSettings.Value;
        }

        [HttpGet]
        public string Get()
        {
            return "I am your communication service";
        }
        [HttpPost]
        public async  Task<bool>Post(EmailData emailData)
        {
            var email = new MimeMessage();
            email.Sender = MailboxAddress.Parse(_mailSettings.Mail);
            email.To.Add(MailboxAddress.Parse(emailData.toAddress));
            email.Subject = emailData.subject;
            var builder = new BodyBuilder();
     
            builder.HtmlBody = emailData.message;
            email.Body = builder.ToMessageBody();
            using var smtp = new SmtpClient();
            smtp.Connect(_mailSettings.Host, _mailSettings.Port, SecureSocketOptions.StartTls);
            smtp.Authenticate(_mailSettings.Mail, _mailSettings.Password);
            await smtp.SendAsync(email);
            smtp.Disconnect(true);
            return true;
        }
    }
    public class EmailData
    {
        public string toAddress { get; set; }
        public string message { get; set; }
        public string subject { get; set; }

    }

}
