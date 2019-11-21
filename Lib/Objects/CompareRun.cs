using AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;
using System.Text;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CompareRun
    {
        public string first_run_id { get; set; }
        public string second_run_id { get; set; }

        public bool file_system { get; set; }
        public bool ports { get; set; }
        public bool users { get; set; }
        public bool services { get; set; }
        public bool registry { get; set; }
        public bool certificates { get; set; }
        public bool firewall { get; set; }
        public bool comobjects { get; set; }
        public bool eventlogs { get; set; }
        public int type { get; set; }
        public string timestamp { get; set; }
        public string version { get; set; }
        public PLATFORM platform { get; set; }
    }
}
