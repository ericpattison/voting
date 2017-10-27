using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using svc_tournament.Models;

namespace svc_tournament.Controllers {
    [Route("api/[controller]")]
    public class SummaryController : Controller {
        
        [HttpGet]
        public IActionResult GetSummaries() {
            return null;
        }

        [HttpGet]
        public IActionResult GetDetails() {
            return null;
        }

    }
}