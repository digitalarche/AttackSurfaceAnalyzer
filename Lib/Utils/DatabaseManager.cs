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
using System.Linq;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class DatabaseManager
    {
        private static LiteDatabase db;

        public static bool FirstRun { get; private set; } = true;

        public static bool Setup(string filename)
        {
            db = new LiteDatabase(filename);
            return true;
        }

        public static PLATFORM RunIdToPlatform(string runid)
        {
            var col = db.GetCollection<CollectRun>("CollectRuns");

            var results = col.Find(x => x.run_id.Equals(runid));
            if (results.Any())
            {
                return results.First().platform;
            }
            else
            {
                return PLATFORM.UNKNOWN;
            }
        }

        public static List<RawCollectResult> GetResultsByRunid(string runid)
        {
            var col = db.GetCollection<RawCollectResult>("CollectResults");

            return col.Find(x => x.RunId.Equals(runid)).ToList()
        }

        public static void InsertAnalyzed(CompareResult objIn)
        {
            var col = db.GetCollection<CompareResult>("AnalysisResults");
            col.Insert(objIn);
        }

        public static void VerifySchemaVersion()
        {
            return;
        }

        public static List<string> GetLatestRunIds(int numberOfIds, string type)
        {
            List<string> output = new List<string>();

            if (type.Equals("collect"))
            {
                var col = db.GetCollection<RawCollectResult>("CollectResults");


                var numFound = 0;
                var res = col.FindAll();
                while (numFound < numberOfIds)
                {
                    output.Add(res.Take(1).First().RunId);
                }
            }

            return output;

        }

        public static Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId)
        {
            var types = GetResultTypes(runId);
            var output = new Dictionary<RESULT_TYPE, int>();
            var col = db.GetCollection<RawCollectResult>("CollectResults");

            foreach (var type in types)
            {
                if (type.Value)
                {
                    output[type.Key] = col.Find(x => x.RunId.Equals(runId) && x.ResultType.Equals(type.Key)).Count();
                }
                else
                {
                    output[type.Key] = 0;
                }
            }

            return output;
        }

        public static Dictionary<RESULT_TYPE, bool> GetResultTypes(string runId)
        {
            var col = db.GetCollection<CollectRun>("CollectRuns");

            var res = col.FindOne(x => x.run_id.Equals(runId));

            Dictionary<RESULT_TYPE, bool> output = new Dictionary<RESULT_TYPE, bool>()
            {
                { RESULT_TYPE.CERTIFICATE, res.certificates},
                { RESULT_TYPE.COM, res.comobjects},
                { RESULT_TYPE.FILE, res.file_system},
                { RESULT_TYPE.FIREWALL, res.firewall},
                { RESULT_TYPE.LOG, res.eventlogs},
                { RESULT_TYPE.PORT, res.ports},
                { RESULT_TYPE.REGISTRY, res.registry},
                { RESULT_TYPE.SERVICE, res.services},
                { RESULT_TYPE.USER, res.users}
            };

            return output;
        }

        public static void CloseDatabase()
        {
            db.Dispose();
            db = null;
        }

        public static void Write(CollectObject objIn, string runId)
        {
            var col = db.GetCollection<RawCollectResult>("CollectResults");

            var insertion = new RawCollectResult()
            {
                CollectObject = objIn,
                RunId = runId,
            };

            col.Insert(insertion);
        }

        public static List<RawCollectResult> GetMissingFromFirst(string firstRunId, string secondRunId)
        {

        }

        public static List<RawModifiedResult> GetModified(string firstRunId, string secondRunId);

        public static void DeleteRun(string runid);

    }
}
