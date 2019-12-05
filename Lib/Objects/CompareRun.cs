using AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;
using System.Text;

namespace AttackSurfaceAnalyzer.Objects
{
    public class CompareRun
    {
        public string BaseRunId { get; set; }
        public string CompareRunId { get; set; }
        public string Timestamp { get; set; }
        public string Version { get; set; }
        public string Platform { get; set; }
        public string PlatformVersion { get; set; }
        public int Id { get; set; }
        public RUN_STATUS RunStatus { get; set; }
    }
}
