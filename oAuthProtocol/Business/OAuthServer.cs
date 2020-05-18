using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Newtonsoft.Json;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace oAuthProtocol.Business
{
    public class OAuthServer : IOAuthServer
    {
        private int CodeExpiration = 0; // 60 seconds
        private int TokenExpiration = 0; // 3600 seconds
        private string CodePrepend = "code_";
        private string TokenPrepend = "token_";
        private string RefreshPrepend = "refresh_";

        private readonly IMemoryCache memoryCache;
        private readonly IHttpContextAccessor httpContextAccessor;
        private readonly IOptions<OAuthApiConfig> oAuthApiConfig;
        private readonly ILogger<OAuthServer> logger;

        public OAuthServer(IMemoryCache memoryCache,
            IHttpContextAccessor httpContextAccessor,
            IOptions<OAuthApiConfig> oAuthApiConfig,
            ILogger<OAuthServer> logger)
        {
            this.memoryCache = memoryCache;
            this.httpContextAccessor = httpContextAccessor;
            this.oAuthApiConfig = oAuthApiConfig;
            this.logger = logger;

            CodeExpiration = oAuthApiConfig.Value.CodeExpiration; // 60 seconds
            TokenExpiration = oAuthApiConfig.Value.TokenExpiration; // 3600 seconds
        }

        public async Task<string> Authorize(string clientID, string responseType, string redirectUri, string state, string scope)
        {
            try
            {
                Cleaning();

                logger.LogInformation("Start Authorize");

                logger.LogDebug("client_id:" + clientID);
                logger.LogDebug("response_type:" + responseType);
                logger.LogDebug("redirect_uri:" + redirectUri);
                logger.LogDebug("state:" + state);
                logger.LogDebug("scope:" + scope);

                AuthorizationResult authorizationResult = new AuthorizationResult();

                if (responseType != "code")
                {
                    Error(redirectUri, "unsupported_response_type", "Only code response_type is supported", state);
                    logger.LogWarning("unsupported_response_type:" + state);

                    authorizationResult.Result = "unsupported_response_type:" + state;
                    authorizationResult.Status = -1;

                    return JsonConvert.SerializeObject(authorizationResult);
                }
                if (!await VerifyClientId(clientID, redirectUri, state))
                {
                    logger.LogWarning("Validation Error");

                    authorizationResult.Result = "Validation Error";
                    authorizationResult.Status = -2;

                    return JsonConvert.SerializeObject(authorizationResult);
                }

                httpContextAccessor.HttpContext.Session.SetString("client_id", clientID);
                httpContextAccessor.HttpContext.Session.SetString("response_type", responseType);
                httpContextAccessor.HttpContext.Session.SetString("redirect_uri", redirectUri);
                httpContextAccessor.HttpContext.Session.SetString("state", state);
                httpContextAccessor.HttpContext.Session.SetString("scope", scope);

                authorizationResult.Result = "Authorization succeeded.";
                authorizationResult.Status = 0;

                return JsonConvert.SerializeObject(authorizationResult);
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return "An unexpected error has occurred.";
            }
        }

        public async Task<string> Authenticate(string user, string password)
        {
            try
            {
                logger.LogDebug("Start Authentication: ");
                logger.LogDebug("user:" + user);

                if (httpContextAccessor.HttpContext.Session.GetString("client_id") == null)
                {
                    logger.LogWarning("Session Expired");
                    return "Session Expired";
                }

                string client_id = httpContextAccessor.HttpContext.Session.GetString("client_id");
                List<ClientData> data = await GetClientData();
                string auth_group = data.Where(r => r.ClientID == client_id).ElementAt(0).AuthGroup;

                User userAuthenticationResult = VerifyAuthentication(user, password, auth_group);
                if (!userAuthenticationResult.Valid)
                {
                    logger.LogWarning("Authentication failed");
                    return "Authentication failed";
                }

                logger.LogDebug("Authentication successed");
                ISession session = httpContextAccessor.HttpContext.Session;

                string code = GetRandomCode(new Random());

                memoryCache.Set(CodePrepend + code, userAuthenticationResult);

                string urlRedirect = "{0}?code={1}";
                urlRedirect = string.Format(urlRedirect, session.GetString("redirect_uri"), code);
                string state = session.GetString("state");

                if (state != null && state != "")
                {
                    urlRedirect += "&state=" + state;
                }

                logger.LogDebug("Redirect to:" + urlRedirect);

                AuthenticateResult authenticateResult = new AuthenticateResult();

                authenticateResult.Code = code;
                authenticateResult.RedirectUri = session.GetString("redirect_uri");
                authenticateResult.State = state;

                return JsonConvert.SerializeObject(authenticateResult);
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return "An unexpected error has occurred.";
            }
        }

        public async Task<string> GetToken(string grantType, string clientID, string clientSecret, string code, string redirectUri, string refresh)
        {
            try
            {
                logger.LogDebug("Start GetToken");

                Cleaning();
                ISession session = httpContextAccessor.HttpContext.Session;

                logger.LogDebug("grant_type:" + grantType);
                logger.LogDebug("client_id:" + clientID);
                logger.LogDebug("client_secret:" + clientSecret);
                logger.LogDebug("code:" + code);
                logger.LogDebug("redirect_uri:" + redirectUri);

                if (grantType == "authorizationCode")
                {
                    if (!await VerifyClientIDAndSecret(clientID, clientSecret, redirectUri))
                    {
                        logger.LogWarning("Validation Error");
                        return JsonConvert.SerializeObject("Validation Error");
                    }
                    
                    if (memoryCache.Get(CodePrepend + code) == null)
                    {
                        Error(redirectUri, "invalid_grant", "Not valid code.", null);
                        logger.LogWarning("Not valid code.");
                        return ("Not valid code.");
                    }
                    
                    User userData = (User)memoryCache.Get(CodePrepend + code);

                    if (DateTime.Now.Subtract(userData.timestamp).TotalSeconds > CodeExpiration)
                    {
                        Error(redirectUri, "invalid_grant", "Code is expired. Max duration is " + CodeExpiration + " sec.", null);
                        logger.LogWarning("Code is expired. Max duration is " + CodeExpiration + " sec.");

                        return "Code is expired. Max duration is " + CodeExpiration + " sec.";
                    }

                    Random random = new Random();

                    Token token = new Token(GetRandomCode(random), GetRandomCode(random), TokenExpiration);
                    memoryCache.Set(TokenPrepend + token.AccessToken, userData);
                    memoryCache.Set(RefreshPrepend + token.RefreshToken, token);

                    logger.LogDebug("Return Token:" + Newtonsoft.Json.Linq.JObject.FromObject(token).ToString());

                    TokenResult tokenResult = new TokenResult();

                    tokenResult.access_token = token.AccessToken;
                    tokenResult.expires_in = TokenExpiration;
                    tokenResult.refresh_token = token.RefreshToken;

                    return JsonConvert.SerializeObject(tokenResult);
                }
                else if (grantType == "refreshToken")
                {
                    if (!await VerifyClientIDAndSecret(clientID, clientSecret, redirectUri))
                    {
                        logger.LogWarning("Validation Error");
                        return JsonConvert.SerializeObject("Validation Error");
                    }

                    Token token = (Token)memoryCache.Get(RefreshPrepend + refresh);
                    User userData = (User)memoryCache.Get(TokenPrepend + token.AccessToken);
                    // delete old
                    memoryCache.Remove(TokenPrepend + token.AccessToken);
                    memoryCache.Remove(RefreshPrepend + token.RefreshToken);
                    //save new
                    Random random = new Random();
                    token = new Token(GetRandomCode(random), GetRandomCode(random), TokenExpiration);
                    memoryCache.Set(TokenPrepend + token.AccessToken, userData);
                    memoryCache.Set(RefreshPrepend + token.RefreshToken, token);

                    TokenResult tokenResult = new TokenResult();

                    tokenResult.access_token = token.AccessToken;
                    tokenResult.expires_in = TokenExpiration;
                    tokenResult.refresh_token = token.RefreshToken;

                    return JsonConvert.SerializeObject(tokenResult);
                }
                else
                {
                    Error(session.GetString("redirect_uri"), "invalid_grant", "The provided access grant is invalid", session.GetString("state"));
                    logger.LogWarning("The provided access grant is invalid");

                    return JsonConvert.SerializeObject("The provided access grant is invalid");
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return "An unexpected error has occurred.";
            }
        }
        private void Error(string redirectUri, string error, string errorDescription, string state)
        {
            string urlRedirect = "{0}?error={1}&error_description={2}";
            if (state != null && state != "")
            {
                urlRedirect += "&state=" + state;
            }
            urlRedirect = string.Format(urlRedirect, redirectUri, error, errorDescription, state);
        }

        private async Task<bool> VerifyClientId(string clientID, string redirectUri, string state)
        {
            try
            {
                List<ClientData> data = await GetClientData();

                if (data.Where(r => r.ClientID == clientID).Count() == 0)
                {
                    Error(redirectUri, "invalid_client", "The client identifier provided is invalid.", state);
                    logger.LogWarning("The client identifier provided is invalid.");
                    return false;
                }
                if (!redirectUri.StartsWith(data.Where(r => r.ClientID == clientID).First().RedirectUri))
                {
                    Error(redirectUri, "redirect_uri_mismatch", "The redirection URI provided does not match a pre-registered value.", state);
                    logger.LogWarning("The redirection URI provided does not match a pre-registered value.");
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return false;
            }
        }

        private async Task<bool> VerifyClientIDAndSecret(string client_id, string client_secret, string redirect_uri)
        {
            try
            {
                List<ClientData> data = await GetClientData();

                if (data.Where(r => r.ClientID == client_id).Count() == 0)
                {
                    Error(redirect_uri, "invalid_client", "The client identifier provided is invalid.", null);
                    logger.LogWarning("The client identifier provided is invalid.");
                    return false;
                }
                if (!redirect_uri.StartsWith(data.Where(r => r.ClientID == client_id).First().RedirectUri))
                {
                    Error(redirect_uri, "redirect_uri_mismatch", "The redirection URI provided does not match a pre-registered value.", null);
                    logger.LogWarning("The redirection URI provided does not match a pre-registered value.");
                    return false;
                }
                if (data.Where(r => r.ClientID == client_id).First().ClientSecret != client_secret)
                {
                    Error(redirect_uri, "unauthorized_client", "Bad client_secret. Client secret sent is: " +
                        data.Where(r => r.ClientID == client_id).First().ClientSecret, null);
                    logger.LogWarning("Bad client_secret. Client secret sent is: " + data.Where(r => r.ClientID == client_id).First().ClientSecret);
                    return false;
                }
                return true;
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return false;
            }
        }

        private async Task<List<ClientData>> GetClientData()
        {
            try
            {
                List<ClientData> data = new List<ClientData>();

                string client_id = "987654321";
                string client_secret = "abcdefghilmnopqrstuvzabc";
                string redirect_uri = "localhost";
                string auth_group = "";

                data.Add(new ClientData(client_id, client_secret, redirect_uri, auth_group));

                return data;
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return null;
            }
        }

        static ConcurrentBag<string> cacheKeys = new ConcurrentBag<string>();

        private void Cleaning()
        {
            try
            {
                IMemoryCache applicationState = memoryCache;
                object oauthCleaning = applicationState.Get("oauth_cleaning");

                if (oauthCleaning == null || (DateTime.Now - (DateTime)oauthCleaning).TotalSeconds > 60)
                {
                    applicationState.Set("oauth_cleaning", DateTime.Now);
                    //cleaning

                    
                    foreach (string key in cacheKeys)
                    {
                        if (key.StartsWith(CodePrepend))
                        {
                            if ((DateTime.Now - ((User)applicationState.Get(key)).timestamp).TotalSeconds > CodeExpiration)
                            {
                                applicationState.Remove(key);
                            }
                        }
                        else if (key.StartsWith(TokenPrepend))
                        {
                            if ((DateTime.Now - ((User)applicationState.Get(key)).timestamp).TotalSeconds > TokenExpiration)
                            {
                                applicationState.Remove(key);
                            }
                        }
                        else if (key.StartsWith(RefreshPrepend))
                        {
                            if (applicationState.Get(TokenPrepend + ((Token)applicationState.Get(key)).AccessToken) == null)
                            {
                                applicationState.Remove(key);
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
            }
        }
        private string GetRandomCode(Random random)
        {
            try
            {
                string randomString = string.Empty;
                for (int i = 0; i < 20; i++)
                {
                    string randomTemp = random.Next(9).ToString();
                    randomString = randomString + randomTemp;
                }
                return randomString;
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return null;
            }
        }
        private User VerifyAuthentication(string username, string password, string authGroup)
        {
            try
            {
                User userResult = new User();
                Business.User user = new Business.User();

                //DataTable userInfo = user.Login(username, password);

                userResult.Valid = true;

                return userResult;
            }
            catch (Exception ex)
            {
                logger.LogError(ex.Message + Environment.NewLine + ex.StackTrace);
                return null;
            }
        }
    }
}
