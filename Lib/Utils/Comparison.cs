using System;
using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Utils
{
    public class Comparison
    {
        public string FirstRunId { get; set; }
        public string SecondRunId { get; set; }
        public RUN_STATUS Status { get; set; }
        public int Id { get; set; }

        public Comparison(string firstRunId, string secondRunId, RUN_STATUS status)
        {
            FirstRunId = firstRunId;
            SecondRunId = secondRunId;
            Status = status;
        }
    }
}
