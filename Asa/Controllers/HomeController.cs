// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Models;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace AttackSurfaceAnalyzer.Gui.Controllers
{
    public class HomeController : Controller
    {
        public HomeController()
        {

        }

        public IActionResult Index()
        {
            return View();
        }

        public ActionResult WriteMonitorJson(string RunId, int ResultType, string OutputPath)
        {
            AttackSurfaceAnalyzerClient.WriteMonitorJson(RunId, ResultType, OutputPath);

            return Json(true);
        }

        public ActionResult WriteScanJson(int ResultType, string BaseId, string CompareId, bool ExportAll, string OutputPath)
        {
            AttackSurfaceAnalyzerClient.WriteScanJson(ResultType, BaseId, CompareId, ExportAll, OutputPath);
            return Json(true);
        }

        public ActionResult GetMonitorResults(string RunId, int ResultType, int Offset, int NumResults)
        {
            var MonitorObjects = DatabaseManager.db.GetCollection<MonitorObject>("MonitorObjects");
            var Results = MonitorObjects.Find(x => x.RunId.Equals(RunId) && x.ResultType.Equals(ResultType), skip: Offset, limit: NumResults);
            var CountResults = MonitorObjects.Find(x => x.RunId.Equals(RunId) && x.ResultType.Equals(ResultType)).Count();

            Dictionary<string, object> output = new Dictionary<string, object>()
            {
                { "Results" , Results },
                { "TotalCount", CountResults },
                { "Offset", Offset },
                { "Requested", NumResults },
                { "Actual", Results.Count() }
            };

            return Json(JsonConvert.SerializeObject(output));
        }

        public ActionResult GetResults(string BaseId, string CompareId, int ResultType, int Offset, int NumResults)
        {
            var CompareResults = DatabaseManager.db.GetCollection<CompareResult>("CompareResults");

            var results = CompareResults.Find(x => x.BaseRunId.Equals(BaseId) && x.CompareRunId.Equals(CompareId) && x.ResultType.Equals(ResultType), skip: Offset, limit: NumResults).ToList();

            var count = CompareResults.Find(x => x.BaseRunId.Equals(BaseId) && x.CompareRunId.Equals(CompareId) && x.ResultType.Equals(ResultType)).Count();

            Dictionary<string, object> output = new Dictionary<string, object>();

            output["Results"] = results;
            output["TotalCount"] = count;
            output["Offset"] = Offset;
            output["Requested"] = NumResults;
            output["Actual"] = results.Count;
            return Json(JsonConvert.SerializeObject(output));
        }


        public ActionResult GetResultTypes(string BaseId, string CompareId)
        {
            var ResultTypes = DatabaseManager.GetResultTypes(BaseId, CompareId);

            return Json(ResultTypes);
        }

        public ActionResult GetCollectors()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            string RunId = AttackSurfaceAnalyzerClient.GetLatestRunId();

            foreach (BaseCollector c in AttackSurfaceAnalyzerClient.GetCollectors())
            {
                var fullString = c.GetType().ToString();
                var splits = fullString.Split('.');
                dict.Add(splits[splits.Length - 1], c.IsRunning());
            }
            Dictionary<string, object> output = new Dictionary<string, object>();
            output.Add("RunId", RunId);
            output.Add("Runs", dict);
            return Json(JsonConvert.SerializeObject(output));
        }

        public ActionResult GetLatestRunId()
        {
            return Json(AttackSurfaceAnalyzerClient.GetLatestRunId());
        }

        public ActionResult GetMonitorStatus()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            foreach (BaseMonitor c in AttackSurfaceAnalyzerClient.GetMonitors())
            {
                var fullString = c.GetType().ToString();
                var splits = fullString.Split('.');
                dict.Add(splits[splits.Length - 1], c.RunStatus);
            }

            //@TODO: Also return the RunId
            return Json(JsonConvert.SerializeObject(dict));
        }

        public ActionResult GetComparators()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            foreach (BaseCompare c in AttackSurfaceAnalyzerClient.GetComparators())
            {
                var fullString = c.GetType().ToString();
                var splits = fullString.Split('.');
                dict.Add(splits[splits.Length - 1], c.IsRunning());
            }

            //@TODO: Also return the RunId
            return Json(JsonConvert.SerializeObject(dict));
        }


        public ActionResult StartCollection(string Id, bool File, bool Port, bool Service, bool User, bool Registry, bool Certificates, bool Com, bool Firewall, bool Log)
        {
            CollectCommandOptions opts = new CollectCommandOptions();
            opts.RunId = Id.Trim();
            opts.EnableFileSystemCollector = File;
            opts.EnableNetworkPortCollector = Port;
            opts.EnableServiceCollector = Service;
            opts.EnableRegistryCollector = Registry;
            opts.EnableUserCollector = User;
            opts.EnableCertificateCollector = Certificates;
            opts.EnableComObjectCollector = Com;
            opts.EnableFirewallCollector = Firewall;
            opts.EnableEventLogCollector = Log;

            foreach (BaseCollector c in AttackSurfaceAnalyzerClient.GetCollectors())
            {
                // The GUI *should* prevent us from getting here. But this is extra protection.
                // We won't start new collections while existing ones are ongoing.
                if (c.IsRunning() == RUN_STATUS.RUNNING)
                {
                    return Json(GUI_ERROR.ALREADY_RUNNING);
                }
            }
            AttackSurfaceAnalyzerClient.ClearCollectors();

            if(DatabaseManager.RunExists(Id))
            {
                return Json(GUI_ERROR.UNIQUE_ID);
            }

            Task.Factory.StartNew<int>(() => AttackSurfaceAnalyzerClient.RunCollectCommand(opts));
            return Json(GUI_ERROR.NONE);
        }

        public IActionResult Collect()
        {
            return View();
        }

        public ActionResult ChangeTelemetryState(bool DisableTelemetry)
        {
            AsaTelemetry.SetOptOut(DisableTelemetry);

            return Json(true);
        }

        public ActionResult StartMonitoring(string RunId, string Directory, string Extension)
        {
            if (RunId != null)
            {

                var MonitorRuns = DatabaseManager.db.GetCollection<MonitorRun>("MonitorRuns");
                if (MonitorRuns.FindOne(x => x.RunId.Equals(RunId)).Equals(null)){
                    return Json((int)GUI_ERROR.UNIQUE_ID);
                }

                MonitorRuns.Insert(new MonitorRun()
                {
                    Platform = AsaHelpers.GetPlatformString(),
                    PlatformVersion = AsaHelpers.GetOsVersion(),
                    ResultTypes = new List<RESULT_TYPE>() { RESULT_TYPE.FILE },
                    RunId = RunId,
                    Timestamp = DateTime.Now.ToString("o", CultureInfo.InvariantCulture),
                    RunStatus = RUN_STATUS.RUNNING,
                    Version = AsaHelpers.GetVersionString()
                });

                MonitorCommandOptions opts = new MonitorCommandOptions
                {
                    RunId = RunId,
                    EnableFileSystemMonitor = true,
                    MonitoredDirectories = Directory,
                    FilterLocation = "filters.json"
                };
                AttackSurfaceAnalyzerClient.ClearMonitors();
                return Json((int)AttackSurfaceAnalyzerClient.RunGuiMonitorCommand(opts));
            }
            return Json(-1);
        }

        public ActionResult StopMonitoring()
        {
            return Json(AttackSurfaceAnalyzerClient.StopMonitors());
        }

        [HttpPost]
        public ActionResult RunAnalysisWithAnalyses(string SelectedBaseRunId, string SelectedCompareRunId, IFormFile AnalysisFilterFile)
        {
            var filePath = Path.GetTempFileName();

            CompareCommandOptions opts = new CompareCommandOptions();
            opts.FirstRunId = SelectedBaseRunId;
            opts.SecondRunId = SelectedCompareRunId;
            opts.Analyze = true;
            opts.SaveToDatabase = true;

            if (AnalysisFilterFile != null)
            {
                using (var stream = System.IO.File.Create(filePath))
                {
                    AnalysisFilterFile.CopyTo(stream);
                }
                opts.AnalysesFile = filePath;
            }

            if (AttackSurfaceAnalyzerClient.GetComparators().Where(c => c.IsRunning() == RUN_STATUS.RUNNING).Any())
            {
                return Json("Comparators already running!");
            }

            if (DatabaseManager.ComparisonExists(SelectedBaseRunId, SelectedCompareRunId))
            {
                return Json("Using cached comparison calculations.");
            }
            Task.Factory.StartNew(() => AttackSurfaceAnalyzerClient.CompareRuns(opts));

            return Json("Started Analysis");
        }

        public IActionResult Analyze()
        {
            var model = new DataRunListModel
            {
                SelectedBaseRunId = "-1",
                SelectedCompareRunId = "-1",
                Runs = GetRunModels(),
                SelectedMonitorRunId = "-1",
                MonitorRuns = GetMonitorRunModels(),
            };

            return View(model);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        private static IEnumerable<DataRunModel> GetMonitorRunModels()
        {
            List<string> Runs = AttackSurfaceAnalyzerClient.GetRuns("monitor");

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count; i++)
            {
                runModels.Add(new DataRunModel { Key = Runs[i], Text = Runs[i] });
            }

            return runModels;
        }

        private IEnumerable<DataRunModel> GetRunModels()
        {
            List<string> Runs = AttackSurfaceAnalyzerClient.GetRuns("collect");

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count; i++)
            {
                runModels.Add(new DataRunModel { Key = Runs[i], Text = Runs[i] });
            }

            return runModels;
        }

        private IEnumerable<DataRunModel> GetResultModels()
        {
            List<DataRunModel> output = new List<DataRunModel>();

            using (var cmd = new SqliteCommand(SQL_QUERY_ANALYZED, DatabaseManager.Connection, DatabaseManager.Transaction))
            {
                cmd.Parameters.AddWithValue("@status", RUN_STATUS.COMPLETED);

                using (var reader = cmd.ExecuteReader())
                {
                    while (reader.Read())
                    {
                        output.Add(new DataRunModel { Key = reader["base_run_id"].ToString() + " vs. " + reader["compare_run_id"].ToString(), Text = reader["base_run_id"].ToString() + " vs. " + reader["compare_run_id"].ToString() });
                    }
                }
            }

            return output;
        }
    }
}