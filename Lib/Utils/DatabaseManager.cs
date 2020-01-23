// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using LiteDB;
using Microsoft.Data.Sqlite;
using Mono.Posix;
using Mono.Unix;
using Newtonsoft.Json;
using PeNet.Structures.MetaDataTables;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Utils
{
    public static class DatabaseManager
    {
        private const string SQL_CREATE_RUNS = "create table if not exists runs (run_id text, file_system int, ports int, users int, services int, registry int, certificates int, firewall int, comobjects int, eventlogs int, type text, timestamp text, version text, platform text, unique(run_id))";
        private const string SQL_CREATE_FILE_MONITORED = "create table if not exists file_system_monitored (run_id text, row_key text, timestamp text, change_type int, path text, old_path text, name text, old_name text, extended_results text, notify_filters text, serialized text)";

        private const string SQL_CREATE_COLLECT_RESULTS = "create table if not exists collect (run_id text, result_type text, row_key text, identity text, serialized text)";

        private const string SQL_CREATE_COLLECT_ROW_KEY_INDEX = "create index if not exists i_collect_row_key on collect(row_key)";
        private const string SQL_CREATE_COLLECT_RUN_ID_INDEX = "create index if not exists i_collect_run_id on collect(run_id)";

        private const string SQL_CREATE_COLLECT_RESULT_TYPE_INDEX = "create index if not exists i_collect_result_type on collect(result_type)";

        private const string SQL_CREATE_COLLECT_RUN_KEY_COMBINED_INDEX = "create index if not exists i_collect_row_run on collect(run_id, row_key)";
        private const string SQL_CREATE_COLLECT_RUN_TYPE_COMBINED_INDEX = "create index if not exists i_collect_row_type on collect(run_id, result_type)";
        private const string SQL_CREATE_COLLECT_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_row_type on collect(identity, row_key)";

        private const string SQL_CREATE_COLLECT_RUN_KEY_IDENTITY_COMBINED_INDEX = "create index if not exists i_collect_runid_row_type on collect(run_id, identity, row_key)";

        private const string SQL_CREATE_RESULTS = "create table if not exists results (base_run_id text, compare_run_id text, status text);";

        private const string SQL_CREATE_FINDINGS_RESULTS = "create table if not exists findings (comparison_id text, level int, result_type int, identity text, serialized text)";

        private const string SQL_CREATE_FINDINGS_LEVEL_INDEX = "create index if not exists i_findings_level on findings(level)";

        private const string SQL_CREATE_FINDINGS_RESULT_TYPE_INDEX = "create index if not exists i_findings_result_type on findings(result_type)";
        private const string SQL_CREATE_FINDINGS_IDENTITY_INDEX = "create index if not exists i_findings_identity on findings(identity)";

        private const string SQL_CREATE_FINDINGS_LEVEL_RESULT_TYPE_INDEX = "create index if not exists i_findings_level_result_type on findings(level, result_type)";

        private const string SQL_CREATE_PERSISTED_SETTINGS = "create table if not exists persisted_settings (setting text, value text, unique(setting))";
        private const string SQL_CREATE_DEFAULT_SETTINGS = "insert or ignore into persisted_settings (setting, value) values ('telemetry_opt_out','false'),('schema_version',@schema_version)";

        private const string SQL_GET_RESULT_TYPES_SINGLE = "select * from runs where run_id = @run_id";

        private const string SQL_TRUNCATE_COLLECT = "delete from collect where run_id=@run_id";
        private const string SQL_TRUNCATE_FILES_MONITORED = "delete from file_system_monitored where run_id=@run_id";
        private const string SQL_TRUNCATE_RUN = "delete from runs where run_id=@run_id";
        private const string SQL_TRUNCATE_RESULTS = "delete from results where base_run_id=@run_id or compare_run_id=@run_id";

        private const string SQL_SELECT_LATEST_N_RUNS = "select run_id from runs where type = @type order by timestamp desc limit 0,@limit;";

        private const string SQL_GET_SCHEMA_VERSION = "select value from persisted_settings where setting = 'schema_version' limit 0,1";
        private const string SQL_GET_NUM_RESULTS = "select count(*) as the_count from collect where run_id = @run_id and result_type = @result_type";
        private const string SQL_GET_PLATFORM_FROM_RUNID = "select platform from runs where run_id = @run_id";

        private const string SQL_INSERT_COLLECT_RESULT = "insert into collect (run_id, result_type, row_key, identity, serialized) values (@run_id, @result_type, @row_key, @identity, @serialized)";
        private const string SQL_INSERT_FINDINGS_RESULT = "insert into findings (comparison_id, result_type, level, identity, serialized) values (@comparison_id, @result_type, @level, @identity, @serialized)";

        private const string SQL_GET_COLLECT_MISSING_IN_B = "select * from collect b where b.run_id = @second_run_id and b.identity not in (select identity from collect a where a.run_id = @first_run_id);";
        private const string SQL_GET_COLLECT_MODIFIED = "select a.row_key as 'a_row_key', a.serialized as 'a_serialized', a.result_type as 'a_result_type', a.identity as 'a_identity', a.run_id as 'a_run_id', b.row_key as 'b_row_key', b.serialized as 'b_serialized', b.result_type as 'b_result_type', b.identity as 'b_identity', b.run_id as 'b_run_id' from collect a indexed by i_collect_runid_row_type, collect b indexed by i_collect_runid_row_type where a.run_id=@first_run_id and b.run_id=@second_run_id and a.identity = b.identity and a.row_key != b.row_key;";
        private const string SQL_GET_RESULT_TYPES_COUNTS = "select count(*) as count,result_type from collect where run_id = @run_id group by result_type";

        private const string SQL_GET_RESULTS_BY_RUN_ID = "select * from collect where run_id = @run_id";

        private const string UPDATE_TELEMETRY = "replace into persisted_settings values ('telemetry_opt_out',@TelemetryOptOut)"; //lgtm [cs/literal-as-local]
        private const string CHECK_TELEMETRY = "select value from persisted_settings where setting='telemetry_opt_out'";

        private const string SQL_TRUNCATE = "delete from file_system_monitored where run_id=@run_id";
        private const string SQL_INSERT = "insert into file_system_monitored (run_id, row_key, timestamp, change_type, path, old_path, name, old_name, extended_results, notify_filters, serialized) values (@run_id, @row_key, @timestamp, @change_type, @path, @old_path, @name, @old_name, @extended_results, @notify_filters, @serialized)";

        private const string PRAGMAS = "PRAGMA main.auto_vacuum = 0; PRAGMA main.synchronous = OFF; PRAGMA main.journal_mode = DELETE;";

        private const string INSERT_RUN_INTO_RESULT_TABLE_SQL = "insert into results (base_run_id, compare_run_id, status) values (@base_run_id, @compare_run_id, @status);";
        private const string UPDATE_RUN_IN_RESULT_TABLE = "update results set status = @status where (base_run_id = @base_run_id and compare_run_id = @compare_run_id)";

        private const string SQL_GET_RUN = "select run_id from runs where run_id=@run_id";

        private const string GET_COMPARISON_RESULTS = "select * from findings where comparison_id = @comparison_id and result_type=@result_type order by level des;";
        private const string GET_SERIALIZED_RESULTS = "select change_type, Serialized from file_system_monitored where run_id = @run_id";

        private const string GET_RUNS = "select run_id from runs order by timestamp desc;";

        private const string SQL_QUERY_ANALYZED = "select * from results where status = @status"; //lgtm [cs/literal-as-local]

        private const string SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED = "select * from results where base_run_id=@base_run_id and compare_run_id=@compare_run_id"; //lgtm [cs/literal-as-local]
        private const string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, type, timestamp, version, platform) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @type, @timestamp, @version, @platform)"; //lgtm [cs/literal-as-local]
        private const string SQL_GET_RESULT_TYPES = "select * from runs where run_id = @base_run_id or run_id = @compare_run_id"; //lgtm [cs/literal-as-local]

        private const string GET_MONITOR_RESULTS = "select * from file_system_monitored where run_id=@run_id order by timestamp limit @offset,@limit;"; //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT_MONITORED = "select count(*) from file_system_monitored where run_id=@run_id;"; //lgtm [cs/literal-as-local]

        private const string GET_COMPARISON_RESULTS_LIMIT = "select * from findings where comparison_id=@comparison_id and result_type=@result_type order by level desc limit @offset,@limit;"; //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT = "select count(*) from findings where comparison_id=@comparison_id and result_type=@result_type"; //lgtm [cs/literal-as-local]

        private const string SCHEMA_VERSION = "5";
        private static bool WriterStarted = false;

        public static ConcurrentQueue<WriteObject> WriteQueue { get; private set; } = new ConcurrentQueue<WriteObject>();

        public static bool FirstRun { get; private set; } = true;

        public static LiteDatabase db;

        public static string Filename { get; private set; } = "asa.litedb";

        public static bool Setup(string filename = null)
        {
            if (filename != null)
            {
                if (Filename != filename)
                {

                    if (db != null)
                    {
                        CloseDatabase();
                    }

                    Filename = filename;
                }
            }

            var StopWatch = System.Diagnostics.Stopwatch.StartNew();

            if (System.IO.File.Exists(Filename))
            {
                Log.Debug($"Loading Database {Filename} of size {new FileInfo(Filename).Length}");
            }
            else
            {
                Log.Debug($"Initializing database at {Filename}");
            }
            db = new LiteDatabase($"Filename={Filename};Journal=false;Mode=Exclusive");

            StopWatch.Stop();
            var t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            var answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed opening database in {0}", answer);

            var col = db.GetCollection<WriteObject>("WriteObjects");

            col.EnsureIndex(x => x.IdentityHash);
            col.EnsureIndex(x => x.InstanceHash);
            col.EnsureIndex(x => x.ColObj.ResultType);
            col.EnsureIndex(x => x.RunId);

            var cr = db.GetCollection<CompareResult>("CompareResults");

            cr.EnsureIndex(x => x.BaseRunId);
            cr.EnsureIndex(x => x.CompareRunId);
            cr.EnsureIndex(x => x.ResultType);

            var settings = db.GetCollection<Setting>("Settings");

            SetOptOut(false);

            var res = settings.Count(x => x.Name.Equals("SchemaVersion"));

            if (res == 0)
            {
                settings.Insert(new Setting() { Name = "SchemaVersion", Value = SCHEMA_VERSION });
            }

            if (!WriterStarted)
            {
                ((Action)(async () =>
                {
                    await Task.Run(() => KeepSleepAndFlushQueue()).ConfigureAwait(false);
                }))();
                WriterStarted = true;
            }
                
            return true;
        }

        public static List<DataRunModel> GetResultModels(RUN_STATUS status)
        {
            var output = new List<DataRunModel>();
            var comparisons = db.GetCollection<Comparison>("Comparisons");

            var results = comparisons.Find(x => x.Status.Equals(status));

            foreach(var result in results)
            {
                output.Add(new DataRunModel { Key = result.FirstRunId + " vs. " + result.SecondRunId, Text = result.FirstRunId + " vs. " + result.SecondRunId });
            }

            return output;
        }

        public static void TrimToLatest()
        {
            List<string> Runs = new List<string>();

            var runs = db.GetCollection<Run>("Runs");

            var all = runs.FindAll();

            var allButLatest = all.Except(new List<Run>() { all.Last() });

            foreach(var run in allButLatest)
            {
                DeleteRun(run.RunId);
            }
        }

        public static bool HasElements()
        {
            return !WriteQueue.IsEmpty;
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
            while (!WriteQueue.IsEmpty)
            {
                WriteNext();
            }
            Thread.Sleep(100);
        }

        public static PLATFORM RunIdToPlatform(string runid)
        {
            var col = db.GetCollection<Run>("Runs");

            var results = col.Find(x => x.RunId.Equals(runid));
            if (results.Any())
            {
                return (PLATFORM)Enum.Parse(typeof(PLATFORM), results.First().Platform);
            }
            else
            {
                return PLATFORM.UNKNOWN;
            }
        }

        public static List<WriteObject> GetResultsByRunid(string runid)
        {
            var output = new List<WriteObject>();

            var wo = db.GetCollection<WriteObject>("WriteObjects");

            return wo.Find(x => x.RunId.Equals(runid)).ToList();
        }

        public static void InsertAnalyzed(CompareResult objIn)
        {
            if (objIn != null)
            {
                var cr = db.GetCollection<CompareResult>("CompareResults");

                cr.Insert(objIn);
            }
        }

        public static void VerifySchemaVersion()
        {
            var settings = db.GetCollection<Setting>("Settings");

            if (!(settings.Find(x => x.Name.Equals("SchemaVersion") && x.Value.Equals(SCHEMA_VERSION)).Any()))
            {
                Log.Fatal("Schema version of database is {0} but {1} is required. Use config --reset-database to delete the incompatible database.", settings.FindOne(x => x.Name.Equals("SchemaVersion")).Value, SCHEMA_VERSION);
                Environment.Exit(-1);
            }
        }

        public static List<string> GetLatestRunIds(int numberOfIds, string type)
        {
            var runs = db.GetCollection<Run>("Runs");

            var latest = runs.FindOne(Query.All(Query.Descending));

            return runs.Find(x => x.Id > latest.Id - numberOfIds).Select(x => x.RunId).ToList();
        }

        public static Dictionary<RESULT_TYPE, int> GetResultTypesAndCounts(string runId)
        {
            var outDict = new Dictionary<RESULT_TYPE, int>() { };

            var wo = db.GetCollection<WriteObject>("WriteObjects");

            foreach(RESULT_TYPE resultType in Enum.GetValues(typeof(RESULT_TYPE)))
            {
                var count = wo.Count(x => x.ColObj.ResultType.Equals(resultType));

                if (count > 0)
                {
                    outDict.Add(resultType, count);
                }
            }

            return outDict;
        }

        public static int GetNumResults(RESULT_TYPE ResultType, string runId)
        {
            var wo = db.GetCollection<WriteObject>("WriteObjects");

            return wo.Count(Query.And(Query.EQ("RunId", runId), Query.EQ("ColObj.ResultType", (int)ResultType)));
        }

        public static IEnumerable<FileMonitorEvent> GetSerializedMonitorResults(string runId)
        {
            List<FileMonitorEvent> records = new List<FileMonitorEvent>();

            var fme = db.GetCollection<FileMonitorEvent>("FileMonitorEvents");

            return fme.Find(x => x.RunId.Equals(runId));
        }

        public static void InsertRun(string runId, Dictionary<RESULT_TYPE, bool> dictionary)
        {
            var runs = db.GetCollection<Run>("Runs");

            runs.Insert(new Run() {
                RunId = runId,
                ResultTypes = dictionary,
                Platform = AsaHelpers.GetPlatformString(),
                Timestamp = DateTime.Now.ToString("o", CultureInfo.InvariantCulture),
                Type = (dictionary.ContainsKey(RESULT_TYPE.FILEMONITOR) && dictionary[RESULT_TYPE.FILEMONITOR]) ? RUN_TYPE.MONITOR : RUN_TYPE.COLLECT,
                Version = AsaHelpers.GetVersionString()
            });
        }

        public static Dictionary<RESULT_TYPE, bool> GetResultTypes(string runId)
        {
            var runs = db.GetCollection<Run>("Runs");

            var run = runs.FindOne(x => x.RunId.Equals(runId));

            return run.ResultTypes;
        }

        public static void CloseDatabase()
        {
            db.Dispose();
            db = null;
        }

        public static void Write(CollectObject objIn, string runId)
        {
            if (objIn != null && runId != null)
            {
                WriteQueue.Enqueue(new WriteObject() { ColObj = objIn, RunId = runId });
            }
        }

        public static void InsertCompareRun(string firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            var crs = db.GetCollection<CompareRun>("CompareRun");

            var cr = new CompareRun() { FirstRunId = firstRunId, SecondRunId = secondRunId, Status = runStatus };

            crs.Insert(cr);
        }

        public static void WriteNext()
        {
            var list = new List<WriteObject>();
            for (int i = 0; i < Math.Min(1000,WriteQueue.Count); i++)
            {
                WriteObject ColObj;
                WriteQueue.TryDequeue(out ColObj);
                list.Add(ColObj);
            }

            var col = db.GetCollection<WriteObject>("WriteObjects");
            col.InsertBulk(list);
        }

        public static IEnumerable<WriteObject> GetMissingFromFirst(string firstRunId, string secondRunId)
        {
            var col = db.GetCollection<WriteObject>("WriteObjects");

            var firstRun = col.Find(x => x.RunId.Equals(firstRunId));
            var firstRunIdentities = firstRun.Select(x => x.IdentityHash).ToHashSet();
            var res = col.Find(x => x.RunId.Equals(secondRunId) && !firstRunIdentities.Contains(x.IdentityHash));
            if (res == null)
            {
                return new List<WriteObject>();
            }
            else
            {
                return res;
            }
        }

        public static IEnumerable<Tuple<WriteObject,WriteObject>> GetModified(string firstRunId, string secondRunId)
        {
            var col = db.GetCollection<WriteObject>("WriteObjects");

            var firstRun = col.Find(x => x.RunId.Equals(firstRunId));
            var firstRunIdentities = firstRun.Select(x => x.IdentityHash).ToHashSet();
            var firstRunHashes = firstRun.Select(x => x.InstanceHash).ToHashSet();
            var secondRun = col.Find(x => x.RunId.Equals(secondRunId) && firstRunIdentities.Contains(x.IdentityHash) && !firstRunHashes.Contains(x.InstanceHash));
            return secondRun.Select(x => new Tuple<WriteObject,WriteObject>(x, firstRun.First(x => x.IdentityHash.Equals(x.IdentityHash))));
        }

        public static void UpdateCompareRun(string firstRunId, string secondRunId, RUN_STATUS runStatus)
        {
            var crs = db.GetCollection<CompareRun>("CompareRun");

            var cr = crs.FindOne(x => x.FirstRunId.Equals(firstRunId) && x.SecondRunId.Equals(secondRunId));
            cr.Status = runStatus;
            crs.Update(cr);
        }

        public static void DeleteRun(string runId)
        {
            var Runs = db.GetCollection<Run>("Runs");

            Runs.Delete(x => x.RunId.Equals(runId));

            var Results = db.GetCollection<WriteObject>("WriteObjects");

            Results.Delete(x => x.RunId.Equals(runId));
        }

        public static bool GetOptOut()
        {
            var settings = db.GetCollection<Setting>("Settings");

            return bool.Parse(settings.FindOne(x => x.Name.Equals("TelemetryOptOut")).Value);
        }

        public static void SetOptOut(bool OptOut)
        {
            var settings = db.GetCollection<Setting>("Settings");

            settings.Upsert(new Setting() { Name = "TelemetryOptOut", Value = OptOut.ToString() });
        }

        public static void WriteFileMonitor(FileMonitorObject obj, string runId)
        {
            var fme = db.GetCollection<FileMonitorEvent>();

            fme.Insert(new FileMonitorEvent()
            {
                RunId = runId,
                FMO = obj
            });
        }

        public static Run GetRun(string RunId)
        {
            var runs = db.GetCollection<Run>("Runs");

            return runs.FindOne(x => x.RunId.Equals(RunId));
        }

        public static List<string> GetMonitorRuns()
        {
            return GetRuns("monitor");
        }

        public static List<string> GetRuns(string type)
        {
            var runs = db.GetCollection<Run>("Runs");

            return runs.Find(x => x.Type.Equals(type)).Select(x => x.RunId).ToList();
        }

        public static List<string> GetRuns()
        {
            return GetRuns("collect");
        }

        public static List<FileMonitorEvent> GetMonitorResults(string runId, int offset, int numResults)
        {
            var fme = db.GetCollection<FileMonitorEvent>("FileMonitorEvents");
            return fme.Find(x => x.RunId.Equals(runId), skip: offset, limit: numResults).ToList();
        }

        public static int GetNumMonitorResults(string runId)
        {
            var fme = db.GetCollection<FileMonitorEvent>("FileMonitorEvent");
            return fme.Count(x => x.RunId.Equals(runId));
        }

        public static IEnumerable<CompareResult> GetComparisonResults(string firstRunId, string secondRunId, RESULT_TYPE resultType, int offset = 0, int numResults = 2147483647)
        {
            var crs = db.GetCollection<CompareResult>("CompareResult");

            return crs.Find(x => x.BaseRunId.Equals(firstRunId) && x.CompareRunId.Equals(secondRunId) && x.ResultType.Equals(resultType),offset,numResults);
        }

        public static int GetComparisonResultsCount(string firstRunId, string secondRunId, int resultType)
        {
            var crs = db.GetCollection<CompareResult>("CompareResult");

            return crs.Count(x => x.BaseRunId.Equals(firstRunId) && x.CompareRunId.Equals(secondRunId) && x.ResultType.Equals(resultType));
        }

        public static object GetCommonResultTypes(string baseId, string compareId)
        {
            var json_out = new Dictionary<string, bool>(){
                { "File", false },
                { "Certificate", false },
                { "Registry", false },
                { "Port", false },
                { "Service", false },
                { "User", false },
                { "Firewall", false },
                { "Com", false },
                { "Log", false }
            };

            var runs = db.GetCollection<Run>("Runs");

            var firstRun = runs.FindOne(x => x.RunId.Equals(baseId));
            var secondRun = runs.FindOne(x => x.RunId.Equals(compareId));

            foreach (var collectType in firstRun.ResultTypes)
            {
                if (collectType.Value.Equals(true) && secondRun.ResultTypes[collectType.Key].Equals(true))
                {
                    switch (collectType.Key)
                    {
                        case RESULT_TYPE.FILE:
                            json_out["File"] = true;
                            break;
                        case RESULT_TYPE.CERTIFICATE:
                            json_out["Certificate"] = true;
                            break;
                        case RESULT_TYPE.REGISTRY:
                            json_out["Registry"] = true;
                            break;
                        case RESULT_TYPE.PORT:
                            json_out["Port"] = true;
                            break;
                        case RESULT_TYPE.SERVICE:
                            json_out["Service"] = true;
                            break;
                        case RESULT_TYPE.USER:
                            json_out["User"] = true;
                            break;
                        case RESULT_TYPE.FIREWALL:
                            json_out["Firewall"] = true;
                            break;
                        case RESULT_TYPE.COM:
                            json_out["Com"] = true;
                            break;
                        case RESULT_TYPE.LOG:
                            json_out["Log"] = true;
                            break;
                    }
                }
            }

            return json_out;
        }

        public static bool GetComparisonCompleted(string firstRunId, string secondRunId)
        {
            var cr = db.GetCollection<CompareRun>("CompareRuns");

            return cr.Exists(x => x.FirstRunId.Equals(firstRunId) && x.SecondRunId.Equals(secondRunId));
        }
    }
}
