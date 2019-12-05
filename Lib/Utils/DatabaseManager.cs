// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using LiteDB;
using Mono.Unix;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class DatabaseManager
    {
        private static bool WriterStarted = false;
        public static string DatabaseLocation = "asa.litedb";
        public static ConcurrentQueue<CollectObject> WriteQueue { get; private set; } = new ConcurrentQueue<CollectObject>();
        public static ConcurrentQueue<CompareResult> CompareWriteQueue { get; private set; } = new ConcurrentQueue<CompareResult>();
        public static ConcurrentQueue<MonitorObject> MonitorWriteQueue { get; private set; } = new ConcurrentQueue<MonitorObject>();

        public static bool FirstRun { get; private set; } = true;

        public static LiteDatabase db { get; private set; }

        public static bool Setup(string filename = null)
        {
            if (db != null)
            {
                db.Dispose();
                db = null;
            }

            DatabaseLocation = (filename == null) ? "asa.litedb" : filename;

            db = new LiteDatabase(DatabaseLocation);

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux) || RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                var unixFileInfo = new UnixFileInfo((filename == null) ? "asa.litedb" : filename);
                // set file permission to 666
                unixFileInfo.FileAccessPermissions =
                    FileAccessPermissions.UserRead | FileAccessPermissions.UserWrite
                    | FileAccessPermissions.GroupRead | FileAccessPermissions.GroupWrite
                    | FileAccessPermissions.OtherRead | FileAccessPermissions.OtherWrite;
            }

            var CollectObjects = db.GetCollection<CollectObject>("CollectObjects");

            CollectObjects.EnsureIndex(x => x.RunId);
            CollectObjects.EnsureIndex(x => x.Identity);
            CollectObjects.EnsureIndex(x => x.ResultType);
            CollectObjects.EnsureIndex(x => x.Hash);

            var CollectRuns = db.GetCollection<CollectRun>("CollectRuns");

            CollectRuns.EnsureIndex(x => x.RunId);

            var MonitorObjects = db.GetCollection<MonitorObject>("MonitorObjects");

            MonitorObjects.EnsureIndex(x => x.RunId);
            MonitorObjects.EnsureIndex(x => x.ResultType);

            var MonitorRuns = db.GetCollection<MonitorRun>("MonitorRuns");

            MonitorRuns.EnsureIndex(x => x.RunId);

            var CompareResults = db.GetCollection<CompareResult>("CompareResults");

            CompareResults.EnsureIndex(x => x.BaseRunId);
            CompareResults.EnsureIndex(x => x.CompareRunId);
            CompareResults.EnsureIndex(x => x.Analysis);
            CompareResults.EnsureIndex(x => x.ChangeType);
            CompareResults.EnsureIndex(x => x.ResultType);
            CompareResults.EnsureIndex(x => x.Identity);

            var Settings = db.GetCollection<Setting>("Settings");

            Settings.EnsureIndex(x => x.Name);

            if (Settings.FindOne(x => x.Name.Equals("TelemetryOptOut")) == null)
            {
                var TeleOptOut = new Setting() { Name = "TelemetryOptOut", Value = false };
                Settings.Insert(TeleOptOut);
            }

            if (!WriterStarted)
            {
                ((Action)(async () =>
                {
                    await Task.Run(() => KeepSleepAndFlushQueue()).ConfigureAwait(false);
                }))();
                ((Action)(async () =>
                {
                    await Task.Run(() => KeepSleepAndFlushCompareQueue()).ConfigureAwait(false);
                }))();
                WriterStarted = true;
                return true;
            }
            return false;
        }

        public static bool HasCollectElements()
        {
            return !WriteQueue.IsEmpty;
        }

        public static bool HasCompareElements()
        {
            return !CompareWriteQueue.IsEmpty;
        }

        public static bool HasMonitorElements()
        {
            return !CompareWriteQueue.IsEmpty;
        }

        public static void KeepSleepAndFlushQueue()
        {
            while (true)
            {
                SleepAndFlushQueue();
            }
        }
        public static void SleepAndFlushQueue()
        {
            var col = db.GetCollection<CollectObject>("CollectObjects");
            var toWrite = new List<CollectObject>();
            while (!WriteQueue.IsEmpty)
            {
                CollectObject result;
                WriteQueue.TryDequeue(out result);
                if (result != null)
                {
                    toWrite.Add(result);
                }
            }
            col.InsertBulk(toWrite);
            Thread.Sleep(500);
        }

        public static void KeepSleepAndFlushCompareQueue()
        {
            while (true)
            {
                SleepAndFlushCompareQueue();
            }
        }

        public static void SleepAndFlushCompareQueue()
        {
            var col = db.GetCollection<CompareResult>("CompareResults");
            var toWrite = new List<CompareResult>();
            while (!CompareWriteQueue.IsEmpty)
            {
                CompareResult result;
                CompareWriteQueue.TryDequeue(out result);
                if (result != null)
                {
                    toWrite.Add(result);
                }
            }
            col.InsertBulk(toWrite);
            Thread.Sleep(500);
        }

        public static void KeepSleepAndFlushMonitorQueue()
        {
            while (true)
            {
                SleepAndFlushCompareQueue();
            }
        }

        public static void SleepAndFlushMonitorQueue()
        {
            var col = db.GetCollection<MonitorObject>("MonitorObjects");
            var toWrite = new List<MonitorObject>();
            while (!MonitorWriteQueue.IsEmpty)
            {
                MonitorObject result;
                MonitorWriteQueue.TryDequeue(out result);
                if (result != null)
                {
                    toWrite.Add(result);
                }
            }
            col.InsertBulk(toWrite);
            Thread.Sleep(500);
        }

        public static PLATFORM RunIdToPlatform(string runid)
        {
            var CollectRuns = db.GetCollection<CollectRun>("CollectRuns");
            var results = CollectRuns.Find(x => x.RunId.Equals(runid));
            if (results.Any())
            {
                return results.First().Platform;
            }
            else
            {
                return PLATFORM.UNKNOWN;
            }
        }

        public static List<CollectObject> GetResultsByRunid(string runid)
        {
            var CollectObjects = db.GetCollection<CollectObject>("CollectObjects");
            return CollectObjects.Find(x => x.RunId.Equals(runid)).ToList();
        }

        public static void InsertAnalyzed(CompareResult objIn)
        {
            CompareWriteQueue.Enqueue(objIn);
        }

        public static List<RESULT_TYPE> GetResultTypes(string runId)
        {
            var CollectRuns = db.GetCollection<CollectRun>("CollectRuns");
            var result = CollectRuns.FindOne(x => x.RunId.Equals(runId));

            return result.ResultTypes;
        }

        public static List<RESULT_TYPE> GetResultTypes(string firstRunId, string secondRunId)
        {
            var CollectRuns = db.GetCollection<CollectRun>("CollectRuns");
            var result = CollectRuns.FindOne(x => x.RunId.Equals(firstRunId));
            var result2 = CollectRuns.FindOne(x => x.RunId.Equals(secondRunId));

            return result.ResultTypes.Intersect(result2.ResultTypes).ToList();
        }

        public static void Write(CollectObject objIn, string runId)
        {
            if (objIn != null && runId != null)
            {
                objIn.RunId = runId;
                WriteQueue.Enqueue(objIn);
            }
        }
        public static void Write(MonitorObject objIn)
        {
            if (objIn != null && objIn.RunId != null)
            {
                MonitorWriteQueue.Enqueue(objIn);
            }
        }

        public static void Write(CollectObject objIn)
        {
            if (objIn != null && objIn.RunId != null)
            {
                WriteQueue.Enqueue(objIn);
            }
        }

        public static bool RunExists(string runid)
        {
            var CollectRuns = db.GetCollection<CollectRun>("CollectRuns");
            if (CollectRuns.FindOne(x => x.RunId.Equals(runid)) == null)
            {
                return false;
            }
            return true;
        }

        /// <summary>
        /// Returns a list of CollectObjects which contain identities present in `secondRunId` but missing in `firstRunId`.
        /// </summary>
        /// <param name="firstRunId"></param>
        /// <param name="secondRunId"></param>
        /// <returns></returns>
        public static List<CollectObject> GetMissingFromFirst(string firstRunId, string secondRunId)
        {
            var col = db.GetCollection<CollectObject>("CollectObjects");

            var res1 = col.Find(Query.EQ("Collect.RunId", firstRunId));
            var res2 = col.Find(Query.EQ("Collect.RunId", secondRunId));
            var res1_ids = (from x in res1 select x.Identity);
            var MissingList = res2.Where(x => !res1_ids.Contains(x.Identity)).ToList();

            List<CollectObject> output = new List<CollectObject>();

            foreach (var Missing in MissingList)
            {
                output.Add(Missing);
            }

            return output;
        }

        public static List<Tuple<CollectObject, CollectObject>> GetModified(string firstRunId, string secondRunId)
        {
            var col = db.GetCollection<CollectObject>("CollectObjects");

            var res1 = col.Find(Query.EQ("Collect.RunId", firstRunId));
            var res2 = col.Find(Query.EQ("Collect.RunId", secondRunId));
            var res1_ids = (from x in res1 select x.Identity);
            var res = res2.Where(x => res1_ids.Contains(x.Identity) && (x.Hash != res1.Where(y => y.Identity.Equals(x.Identity)).First().Hash));

            List<Tuple<CollectObject, CollectObject>> rawModifiedResults = new List<Tuple<CollectObject, CollectObject>>();

            foreach (var r in res)
            {
                rawModifiedResults.Add(new Tuple<CollectObject, CollectObject>(col.FindOne(Query.And(Query.EQ("RunId", firstRunId), Query.EQ("Identity", r.Identity))),r));
            }

            return rawModifiedResults;
        }
        public static Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId)
        {
            var types = GetResultTypes(runId);
            var output = new Dictionary<RESULT_TYPE, int>();
            var col = db.GetCollection<CollectObject>("CollectObjects");

            foreach (var type in types)
            {
                output[type] = col.Count(x => x.RunId.Equals(runId) && x.ResultType.Equals(type));
            }

            return output;
        }

        public static List<string> GetLatestCollectRunIds(int numberOfIds)
        {
            List<string> output = new List<string>();

            var col = db.GetCollection<CollectRun>("CollectRuns");

            var results = col.Find(Query.All(Query.Descending), limit: numberOfIds);

            foreach (var res in results)
            {
                output.Add(res.RunId);
            }

            return output;
        }

        public static List<string> GetLatestMonitorRunIds(int numberOfIds)
        {
            List<string> output = new List<string>();

            var col = db.GetCollection<MonitorRun>("MonitorRuns");

            var results = col.Find(Query.All(Query.Descending), limit: numberOfIds);

            foreach (var res in results)
            {
                output.Add(res.RunId);
            }

            return output;
        }

        public static void CloseDatabase()
        {
            db.Dispose();
            db = null;
        }

        public static void DeleteRun(string runid)
        {
            var col = db.GetCollection<CollectObject>("CollectObjects");
            col.Delete(x => x.RunId.Equals(runid));

            var col2 = db.GetCollection<CollectRun>("CollectRuns");
            col2.Delete(x => x.RunId.Equals(runid));

            var col3 = db.GetCollection<CompareRun>("CompareRuns");
            col3.Delete(x => x.BaseRunId.Equals(runid) || x.CompareRunId.Equals(runid));

            var col4 = db.GetCollection<CompareResult>("CompareResults");
            col4.Delete(x => x.BaseRunId.Equals(runid) || x.CompareRunId.Equals(runid));
        }
        
        public static bool TelemetryOptedOut()
        {
            var Settings = db.GetCollection<Setting>("Settings");
            var TeleOptOut = Settings.FindOne(x => x.Name.Equals("TelemetryOptOut"));
            return (bool)TeleOptOut.Value;
        }

        public static void SetTelemetryOptOut(bool optOutStatus)
        {
            var Settings = db.GetCollection<Setting>("Settings");
            var TeleOptOut = Settings.FindOne(x => x.Name.Equals("TelemetryOptOut"));
            TeleOptOut.Value = optOutStatus;
            Settings.Update(TeleOptOut);
        }

        public static bool ComparisonExists(string FirstRunId, string SecondRunId)
        {
            var CompareRuns = db.GetCollection<CompareRun>("CompareRuns");
            var result = CompareRuns.FindOne(x => x.BaseRunId.Equals(FirstRunId) && x.CompareRunId.Equals(SecondRunId));
            return !(result == null);
        }

        public static List<CollectRun> GetCollectRuns()
        {
            var CollectRuns = db.GetCollection<CollectRun>("CollectRuns");
            return CollectRuns.FindAll().ToList();
        }

        public static List<MonitorRun> GetMonitorRuns()
        {
            var MonitorRuns = db.GetCollection<MonitorRun>("MonitorRuns");
            return MonitorRuns.FindAll().ToList();
        }

        public static List<CompareResult> GetCompareResults(RESULT_TYPE ResultType)
        {
            var CompareResults = db.GetCollection<CompareResult>("CompareResults");
            return CompareResults.Find(x => x.ResultType == ResultType).ToList();
        }

        public static List<MonitorObject> GetMonitorObjects(string RunId, int ResultType)
        {
            var MonitorObjects = db.GetCollection<MonitorObject>("MonitorObjects");
            return MonitorObjects.Find(x => x.RunId == RunId).ToList();
        }
    }
}
