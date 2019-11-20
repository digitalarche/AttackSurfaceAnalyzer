// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using LiteDB;
using Microsoft.Data.Sqlite;
using Mono.Unix;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Utils
{
    public abstract class DatabaseBackend
    {
        public bool FirstRun { get; private set; } = true;

        public abstract bool Setup(string filename);

        public abstract bool IsFlushing();

        public abstract PLATFORM RunIdToPlatform(string runid);

        public abstract List<RawCollectResult> GetResultsByRunid(string runid);

        public abstract void InsertAnalyzed(CompareResult objIn);

        public abstract void VerifySchemaVersion();

        public abstract List<string> GetLatestRunIds(int numberOfIds, string type);

        public abstract Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId);

        public abstract Dictionary<RESULT_TYPE, bool> GetResultTypes(string runId);

        public abstract void CloseDatabase();

        public abstract void Write(CollectObject objIn, string runId);

        public abstract List<RawCollectResult> GetMissingFromFirst(string firstRunId, string secondRunId);

        public abstract List<RawModifiedResult> GetModified(string firstRunId, string secondRunId);

        public abstract void DeleteRun(string runid);
        
    }
}
