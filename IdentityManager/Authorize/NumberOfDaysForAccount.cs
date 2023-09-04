using IdentityManager.Data;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace IdentityManager.Authorize
{
    public class NumberOfDaysForAccount : INumberOfDaysForAccount
    {
        private readonly ApplicationDbContext _db;
        public NumberOfDaysForAccount(ApplicationDbContext db)
        {
            _db = db;
        }

        public int Get(string userId)
        {
            var user = _db.ApplicationUser.FirstOrDefault(u => u.Id == userId);
            if (user != null && user.DateCreated != DateTime.MinValue)
            {
                var d = DateTime.Today - user.DateCreated;
                Console.WriteLine(d.Value.Days);
                return d.Value.Days;
            }
            return 1000;
        }
    }
}