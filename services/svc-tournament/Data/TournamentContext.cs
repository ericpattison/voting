using Microsoft.EntityFrameworkCore;

namespace svc_tournament.Data {
    public class TournamentContext : DbContext {
        public TournamentContext() {

        }
        
        public TournamentContext(DbContextOptions<TournamentContext> options) : base(options) {

        }
    }
}