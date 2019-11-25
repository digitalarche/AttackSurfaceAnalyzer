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
        public static LiteDatabase db;

        public static string Filename { get; set; }

        public static bool FirstRun { get; private set; } = true;

        public static bool Setup(string filename)
        {
            if (db != null)
            {
                CloseDatabase();
            }
            db = new LiteDatabase(filename);
            Filename = filename;

            var col = db.GetCollection<Setting>("Settings");

            var res = col.Count(x => x.Name.Equals("TelemetryOptOut"));

            if (res == 0)
            {
                col.Insert(new Setting() { Name = "TelemetryOptOut", Value = "False" });

            }

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

        public static List<CollectObject> GetResultsByRunid(string runid)
        {
            var col = db.GetCollection<CollectObject>("CollectObjects");

            return col.Find(x => x.RunId.Equals(runid)).ToList();
        }

        public static void InsertAnalyzed(CompareResult objIn)
        {
            var col = db.GetCollection<CompareResult>("CompareResults");
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
                var col = db.GetCollection<CollectObject>("CollectObjects");

                var results = col.Find(Query.All(Query.Descending), limit: numberOfIds);

                foreach(var res in results)
                {
                    output.Add(res.RunId);
                }
            }

            return output;

        }

        public static List<string> GetRuns()
        {
            List<string> output = new List<string>();

            var col = db.GetCollection<CollectObject>("CollectObjects");

            var results = col.Find(Query.All(Query.Descending));

            foreach (var collectObject in results)
            {
                output.Add(collectObject.RunId);
            }

            return output;
        }

        public static Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId)
        {
            var types = GetResultTypes(runId);
            var output = new Dictionary<RESULT_TYPE, int>();
            var col = db.GetCollection<CollectObject>("CollectObjects");

            foreach (var type in types)
            {
                if (type.Value)
                {
                    output[type.Key] = col.Count(x => x.RunId.Equals(runId) && x.ResultType.Equals(type.Key));
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

        public static void Write(CollectObject objIn)
        {
            var col = db.GetCollection<CollectObject>("CollectObjects");
            col.Insert(objIn);
        }

        public static void Write(IEnumerable<CollectObject> objsIn)
        {
            var col = db.GetCollection<CollectObject>("CollectObjects");
            col.InsertBulk(objsIn);
        }

        public static List<CollectObject> GetMissingFromFirst(string firstRunId, string secondRunId)
        {
            var col = db.GetCollection<CollectEntry>("CollectResults");

            var res1 = col.Find(Query.EQ("Collect.RunId", firstRunId));
            var res2 = col.Find(Query.EQ("Collect.RunId", secondRunId));
            var res1_ids = (from x in res1 select x.Collect.Identity);
            var MissingList = res2.Where(x => !res1_ids.Contains(x.Collect.Identity)).ToList();
            
            List<CollectObject> output = new List<CollectObject>();
            
            foreach (var Missing in MissingList)
            {
                output.Add(Missing.Collect);
            }

            return output;
        }

        public static List<RawModifiedResult> GetModified(string firstRunId, string secondRunId)
        {
            var col = db.GetCollection<CollectEntry>("CollectResults");

            var res1 = col.Find(Query.EQ("Collect.RunId", firstRunId));
            var res2 = col.Find(Query.EQ("Collect.RunId", secondRunId));
            var res1_ids = (from x in res1 select x.Collect.Identity);
            var res = res2.Where(x => res1_ids.Contains(x.Collect.Identity) && (x.Hash != res1.Where(y => y.Collect.Identity.Equals(x.Collect.Identity)).First().Hash));

            List<RawModifiedResult> rawModifiedResults = new List<RawModifiedResult>();

            foreach(var r in res)
            {
                rawModifiedResults.Add(new RawModifiedResult()
                {
                    First = col.FindOne(Query.And(Query.EQ("RunId", firstRunId), Query.EQ("Identity", r.Collect.Identity))).Collect,
                    Second = r.Collect
                });
            }

            return rawModifiedResults;
        }

        public static void DeleteRun(string runid)
        {
            var col = db.GetCollection<CollectEntry>("CollectEntries");
            col.Delete(x => x.Collect.RunId.Equals(runid));

            var col2 = db.GetCollection<CollectRun>("CollectRuns");
            col2.Delete(x => x.run_id.Equals(runid));
        }

    }
}
