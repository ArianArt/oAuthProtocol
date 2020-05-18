namespace oAuthProtocol.Business
{
    internal class Token
    {
        public string AccessToken { get; set; }
        public int ExpiresIn { get; set; }
        public string RefreshToken { get; set; }

        public Token(string accessToken, string refreshToken, int expiresIn)
        {
            ExpiresIn = expiresIn;
            AccessToken = accessToken;
            RefreshToken = refreshToken;
        }
    }
}