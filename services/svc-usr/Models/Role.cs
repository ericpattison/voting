using System;
using Microsoft.AspNetCore.Identity;

namespace svc_usr.Models {
    public class Role : IdentityRole<Guid> {
        public Role(string name) : base(name) { }
    }
}