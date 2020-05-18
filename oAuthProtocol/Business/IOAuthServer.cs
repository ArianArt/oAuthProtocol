using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace oAuthProtocol.Business
{
    public interface IOAuthServer
    {
        Task<string> Authorize(string clientID, string responseType, string redirectUri, string state, string scope);
        Task<string> Authenticate(string user, string password);
        Task<string> GetToken(string grantType, string clientID, string clientSecret, string code, string redirectUri, string refresh);
    }
}
