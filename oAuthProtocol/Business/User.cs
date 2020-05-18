using System;

namespace oAuthProtocol.Business
{
    internal class User
    {
        public bool Valid = false;
        public int ID { get; set; }
        public string Name { get; set; }
        public string Firstname { get; set; }
        public string Lastname { get; set; }
        public string Email { get; set; }
        public string PhysicalDeliveryOfficeName { get; set; }
        public string Company { get; set; }
        public string St { get; set; }
        public int GroupID { get; set; }
        public DateTime timestamp = DateTime.Now;
    }
}