using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Mvc;
using svc_tournament.Models;

namespace svc_tournament.Controllers {
    [Route("api/[controller]")]
    public class QuestionController : Controller {

        [HttpPost("ask")]
        public IActionResult Ask([FromBody]Ask ask) {
            return Ok();
        }
    }
}