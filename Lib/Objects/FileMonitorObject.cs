// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Newtonsoft.Json;
using Newtonsoft.Json.Serialization;
using System.Reflection;

namespace AttackSurfaceAnalyzer.Objects
{
    public class FileMonitorObject : MonitorObject
    {
        public string Path { get; set; }
        public string OldPath { get; set; }
        public string Name { get; set; }
        public string OldName { get; set; }
        public CHANGE_TYPE ChangeType { get; set; }

        public FileMonitorObject()
        {
            ResultType = RESULT_TYPE.FILE;
        }
    }
}
