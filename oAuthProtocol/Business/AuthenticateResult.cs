namespace oAuthProtocol.Business
{
    internal class AuthenticateResult
    {
        public string RedirectUri { get; set; }

        public string Code { get; set; }

        public string State { get; set; }
    }
}