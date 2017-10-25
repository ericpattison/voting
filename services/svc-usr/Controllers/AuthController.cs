using System.Threading.Tasks;
using System.Linq;
using Microsoft.AspNetCore.Mvc;
using AspNet.Security.OpenIdConnect.Primitives;
using svc_usr.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication;
using AspNet.Security.OpenIdConnect.Server;
using OpenIddict.Core;
using AspNet.Security.OpenIdConnect.Extensions;
using Microsoft.Extensions.Options;
using System.Collections.Generic;

namespace svc_usr.Controllers {
    public class AuthController : Controller {
        private readonly UserManager<Usr> _userManager;
        private readonly SignInManager<Usr> _signInManager;
        private readonly IOptions<IdentityOptions> _identityOptions;
        
        public AuthController(UserManager<Usr> userManager, SignInManager<Usr> signInManager, IOptions<IdentityOptions> identityOptions) {
            _userManager = userManager;
            _signInManager = signInManager;
            _identityOptions = identityOptions;
        }

        [HttpPost("~/connect/token"), Produces("application/json")]
        public async Task<IActionResult> Exchange(OpenIdConnectRequest request) {
            if(request.IsPasswordGrantType()) {
                var user = await _userManager.FindByNameAsync(request.Username);
                if(user == null) {
                    return BadRequest(new OpenIdConnectResponse{
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = "The username/password couple is invalid"
                    });
                }

                var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
                if(!result.Succeeded) {
                    return BadRequest(new OpenIdConnectResponse {
                        Error = OpenIdConnectConstants.Errors.InvalidGrant,
                        ErrorDescription = "The username/password couple is invalid"
                    });
                }

                var ticket = await CreateTicketAsync(request, user);
                return SignIn(ticket.Principal, ticket.Properties, ticket.AuthenticationScheme);
            }

            return BadRequest(new OpenIdConnectResponse {
                Error = OpenIdConnectConstants.Errors.UnsupportedGrantType,
                ErrorDescription = "The specified grant type is not supported"
            });
        }


        [HttpPost("~/api/usr")]
        public async Task<IActionResult> Register([FromBody]Registration model) {
            var user = new Usr { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if(result.Succeeded) {
                return Ok();
            }
            return BadRequest(new {ErrorMessage = result.Errors});
        }

        private async Task<AuthenticationTicket> CreateTicketAsync(OpenIdConnectRequest request, Usr user) {
            var principal = await _signInManager.CreateUserPrincipalAsync(user);
            var ticket = new AuthenticationTicket(principal, new AuthenticationProperties(), OpenIdConnectServerDefaults.AuthenticationScheme);
            ticket.SetScopes(new[]{
                OpenIdConnectConstants.Scopes.OpenId,
                OpenIdConnectConstants.Scopes.Email,
                OpenIdConnectConstants.Scopes.Profile,
                OpenIddictConstants.Scopes.Roles
            }.Intersect(request.GetScopes()));

            ticket.SetResources("resource-server");

            foreach(var claim in ticket.Principal.Claims) {
                if(claim.Type == _identityOptions.Value.ClaimsIdentity.SecurityStampClaimType) continue;

                var destinations = new List<string> {
                    OpenIdConnectConstants.Destinations.AccessToken
                };

                if((claim.Type == OpenIdConnectConstants.Claims.Name && ticket.HasScope(OpenIdConnectConstants.Scopes.Profile)) ||
                    (claim.Type == OpenIdConnectConstants.Claims.Email && ticket.HasScope(OpenIdConnectConstants.Scopes.Email)) ||
                    (claim.Type == OpenIdConnectConstants.Claims.Role && ticket.HasScope(OpenIddictConstants.Claims.Roles))) {

                    destinations.Add(OpenIdConnectConstants.Destinations.IdentityToken);
                }

                claim.SetDestinations(destinations);
            }

            return ticket;
        }
    }
}