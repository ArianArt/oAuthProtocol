namespace oAuthProtocol.Business
{
    internal class ClientData
    {
        public string ClientID { get; set; }
        public string ClientSecret { get; set; }
        public string RedirectUri { get; set; }
        public string AuthGroup { get; set; }

        public ClientData(string clientID, string clientSecret, string redirectUri, string authGroup)
        {
            ClientID = clientID;
            ClientSecret = clientSecret;
            RedirectUri = redirectUri;
            AuthGroup = authGroup;
        }
    }
}