using AttackSurfaceAnalyzer.Types;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CompareRun
    {
        public string FirstRunId { get; set; }
        public string SecondRunId { get; set; }
        public RUN_STATUS Status { get; set; }
    }
}
