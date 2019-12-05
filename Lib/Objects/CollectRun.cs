using AttackSurfaceAnalyzer.Types;
using System;
using System.Collections.Generic;
using System.Text;

namespace AttackSurfaceAnalyzer.Objects
{
    class CollectRun
    {
        public string RunId { get; set; }
        public string Timestamp { get; set; }
        public List<RESULT_TYPE> ResultTypes { get; set; }
        public string Version { get; set; }
        public PLATFORM Platform { get; set; }
        public string PlatformVersion { get; set; }
        public int Id { get; set; }
        public RUN_STATUS RunStatus { get; set; }
    }
}
