using System;

namespace svc_tournament.Data {
    public class RoundData {
        public Guid Id { get; set; }
        public Guid QuestionId { get; set; }
        public uint Round { get; set; }
        public String Content { get; set; }
    }
}