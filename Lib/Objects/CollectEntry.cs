using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.Text;

namespace AttackSurfaceAnalyzer.Objects
{
    class CollectEntry
    {
        public CollectObject Collect;
        public string Hash { get { return CryptoHelpers.CreateHash(JsonConvert.SerializeObject(Collect)); } }
    }
}
