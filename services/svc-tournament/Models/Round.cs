using System;
using System.Collections.Generic;

namespace svc_tournament.Models {
    public class Round {
        public Guid Id { get; set; }
        public List<Answer> Answers { get; set; }
    }
}