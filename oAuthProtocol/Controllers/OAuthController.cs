using oAuthProtocol.Business;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Threading.Tasks;

namespace oAuthProtocol.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class OAuthController : ControllerBase
    {
        private readonly IOAuthServer oAuthServer;
        private readonly ILogger<OAuthController> logger;

        public OAuthController(IOAuthServer oAuthServer,
            ILogger<OAuthController> logger)
        {
            this.oAuthServer = oAuthServer;
            this.logger = logger;
        }


        [HttpGet]
        [Route("Authorize")]
        public async Task<IActionResult> Authorize(string clientID, string responseType, string redirectUri, string state, string scope)
        {
            try
            {
                string jsonResult =await oAuthServer.Authorize(clientID, responseType, redirectUri, state, scope);
                return new JsonResult(jsonResult);
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return StatusCode(400);
            }
        }

        [HttpGet]
        [Route("Authenticate")]
        public async Task<IActionResult> Authenticate(string user, string password)
        {
            try
            {
                string jsonResult = await oAuthServer.Authenticate(user, password);
                return new JsonResult(jsonResult);
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return StatusCode(400);
            }
        }
        [HttpGet]
        [Route("GetToken")]
        public async Task<IActionResult> GetToken(string grantType, string clientID, string clientSecret, string code, string redirectUri, string refresh)
        {
            try
            {
                string jsonResult = await oAuthServer.GetToken(grantType, clientID, clientSecret, code, redirectUri, refresh);
                return new JsonResult(jsonResult);
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return StatusCode(400);
            }
        }
    }
}