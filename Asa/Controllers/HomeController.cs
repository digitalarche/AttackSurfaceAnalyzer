// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Collectors;
using AttackSurfaceAnalyzer.Models;
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.Sqlite;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Gui.Controllers
{
    public class HomeController : Controller
    {
        private const string SQL_QUERY_ANALYZED = "select * from results where status = @status"; //lgtm [cs/literal-as-local]

        private const string SQL_CHECK_IF_COMPARISON_PREVIOUSLY_COMPLETED = "select * from results where base_run_id=@base_run_id and compare_run_id=@compare_run_id"; //lgtm [cs/literal-as-local]
        private const string INSERT_RUN = "insert into runs (run_id, file_system, ports, users, services, registry, certificates, type, timestamp, version, platform) values (@run_id, @file_system, @ports, @users, @services, @registry, @certificates, @type, @timestamp, @version, @platform)"; //lgtm [cs/literal-as-local]
        private const string SQL_GET_RESULT_TYPES = "select * from runs where run_id = @base_run_id or run_id = @compare_run_id"; //lgtm [cs/literal-as-local]

        private const string GET_MONITOR_RESULTS = "select * from file_system_monitored where run_id=@run_id order by timestamp limit @offset,@limit;"; //lgtm [cs/literal-as-local]
        private const string GET_RESULT_COUNT_MONITORED = "select count(*) from file_system_monitored where run_id=@run_id;"; //lgtm [cs/literal-as-local]

        private const string GET_RESULT_COUNT = "select count(*) from findings where comparison_id=@comparison_id and result_type=@result_type"; //lgtm [cs/literal-as-local]

        public HomeController()
        {

        }

        public IActionResult Index()
        {
            return View();
        }

        public ActionResult WriteScanJson(int ResultType, string BaseId, string CompareId, bool ExportAll, string OutputPath)
        {
            AttackSurfaceAnalyzerClient.WriteScanJson(ResultType, BaseId, CompareId, ExportAll, OutputPath);
            return Json(true);
        }

        public ActionResult GetResults(string BaseId, string CompareId, int ResultType, int Offset, int NumResults)
        {
            var col = DatabaseManager.db.GetCollection<CompareResult>("CompareResults");

            var results = new List<CompareResult>();

            var res = col.Find(x => x.BaseRunId.Equals(BaseId) && x.CompareRunId.Equals(CompareId) && x.ResultType.Equals(ResultType), skip: Offset, limit: NumResults);
            var totalCount = col.Count(x => x.BaseRunId.Equals(BaseId) && x.CompareRunId.Equals(CompareId) && x.ResultType.Equals(ResultType));

            Dictionary<string, object> output = new Dictionary<string, object>();

            output["Results"] = results;
            output["TotalCount"] = totalCount;
            output["Offset"] = Offset;
            output["Requested"] = NumResults;
            output["Actual"] = results.Count;
            return Json(JsonConvert.SerializeObject(output));
        }


        public ActionResult GetResultTypes(string BaseId, string CompareId)
        {
            var baseResultTypes = DatabaseManager.GetResultTypes(BaseId);
            var compareResultTypes = DatabaseManager.GetResultTypes(CompareId);

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

            foreach (var resultType in baseResultTypes)
            {
                switch (resultType.Key)
                {
                    case RESULT_TYPE.CERTIFICATE:
                        json_out["Certificate"] = resultType.Value && compareResultTypes.Where(x => x.Value.Equals(resultType.Key)).FirstOrDefault().Value;
                        break;
                    case RESULT_TYPE.COM:
                        json_out["Com"] = resultType.Value && compareResultTypes.Where(x => x.Value.Equals(resultType.Key)).FirstOrDefault().Value;
                        break;
                    case RESULT_TYPE.FILE:
                        json_out["File"] = resultType.Value && compareResultTypes.Where(x => x.Value.Equals(resultType.Key)).FirstOrDefault().Value;
                        break;
                    case RESULT_TYPE.FIREWALL:
                        json_out["Firewall"] = resultType.Value && compareResultTypes.Where(x => x.Value.Equals(resultType.Key)).FirstOrDefault().Value;
                        break;
                    case RESULT_TYPE.LOG:
                        json_out["Log"] = resultType.Value && compareResultTypes.Where(x => x.Value.Equals(resultType.Key)).FirstOrDefault().Value;
                        break;
                    case RESULT_TYPE.PORT:
                        json_out["Port"] = resultType.Value && compareResultTypes.Where(x => x.Value.Equals(resultType.Key)).FirstOrDefault().Value;
                        break;
                    case RESULT_TYPE.REGISTRY:
                        json_out["Registry"] = resultType.Value && compareResultTypes.Where(x => x.Value.Equals(resultType.Key)).FirstOrDefault().Value;
                        break;
                    case RESULT_TYPE.SERVICE:
                        json_out["Service"] = resultType.Value && compareResultTypes.Where(x => x.Value.Equals(resultType.Key)).FirstOrDefault().Value;
                        break;
                    case RESULT_TYPE.USER:
                        json_out["User"] = resultType.Value && compareResultTypes.Where(x => x.Value.Equals(resultType.Key)).FirstOrDefault().Value;
                        break;
                }
            }

            return Json(json_out);
        }

        public ActionResult GetCollectors()
        {
            Dictionary<string, RUN_STATUS> dict = new Dictionary<string, RUN_STATUS>();
            string RunId = AttackSurfaceAnalyzerClient.GetLatestRunId();

            //TODO: Improve this to not have to change this variable on every loop, without having to call GetCollectors twice.
            foreach (BaseCollector c in AttackSurfaceAnalyzerClient.GetCollectors())
            {
                var fullString = c.GetType().ToString();
                var splits = fullString.Split('.');
                dict.Add(splits[splits.Length - 1], c.IsRunning());
            }
            Dictionary<string, object> output = new Dictionary<string, object>();
            output.Add("RunId", RunId);
            output.Add("Runs", dict);
            //@TODO: Also return the RunId
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

            opts.DatabaseFilename = DatabaseManager.Filename;
            opts.FilterLocation = "Use embedded filters.";

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

            var col = DatabaseManager.db.GetCollection<CollectRun>("CollectRuns");

            if (col.Exists(x => x.run_id.Equals(Id)))
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

        public ActionResult RunAnalysis(string firstId, string secondId)
        {

            CompareCommandOptions opts = new CompareCommandOptions();
            opts.FirstRunId = firstId;
            opts.SecondRunId = secondId;
            opts.Analyze = true;
            if (AttackSurfaceAnalyzerClient.GetComparators().Where(c => c.IsRunning() == RUN_STATUS.RUNNING).Any())
            {
                return Json("Comparators already running!");
            }

            var col = DatabaseManager.db.GetCollection<CompareRun>("CompareRuns");

            if (col.Exists(x => x.first_run_id.Equals(firstId) && x.second_run_id.Equals(secondId)))
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
                SelectedMonitorRunId = "-1"
            };

            return View(model);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        
        private IEnumerable<DataRunModel> GetRunModels()
        {
            List<string> Runs = DatabaseManager.GetRuns();

            List<DataRunModel> runModels = new List<DataRunModel>();

            for (int i = 0; i < Runs.Count; i++)
            {
                runModels.Add(new DataRunModel { Key = Runs[i], Text = Runs[i] });
            }

            return runModels;
        }
    }
}