using System;

namespace svc_tournament.Models {
    public class Tournament {
        public Guid Id { get; set; }
        public String Content { get; set; }
        public int Rounds { get; set; }
        public int CurrentRound { get; set; }
    }
}