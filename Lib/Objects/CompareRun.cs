using AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;
using System.Text;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CompareRun
    {
        public int Id { get; set; }
        public string first_run_id { get; set; }
        public string second_run_id { get; set; }
        public string timestamp { get; set; }
        public string version { get; set; }
        public PLATFORM platform { get; set; }
        public RUN_STATUS status { get; set; }
    }
}
