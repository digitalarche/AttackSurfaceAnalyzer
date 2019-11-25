// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text.RegularExpressions;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Collects system event logs.
    /// </summary>
    public class EventLogCollector : BaseCollector
    {
        private bool GatherVerboseLogs;
        public EventLogCollector(string runId, bool GatherVerboseLogs = false)
        {
            this.RunId = runId;
            this.GatherVerboseLogs = GatherVerboseLogs;
        }

        public override IEnumerable<CollectObject> ExecuteInternal()
        {
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                return ExecuteWindows();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
            {
                return ExecuteLinux();
            }
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
            {
                return ExecuteMacOs();
            }

            return Enumerable.Empty<CollectObject>();
        }


        /// <summary>
        /// Collect event logs on Windows using System.Diagnostics.EventLog
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Official documentation for this functionality does not specify what exceptions it throws. https://docs.microsoft.com/en-us/dotnet/api/system.diagnostics.eventlogentrycollection?view=netcore-3.0")]
        public IEnumerable<CollectObject> ExecuteWindows()
        {
            EventLog[] logs = EventLog.GetEventLogs();
            var results = new List<CollectObject>();
            foreach (var log in logs)
            {
                try
                {
                    EventLogEntryCollection coll = log.Entries;

                    foreach (EventLogEntry entry in coll)
                    {
                        if (GatherVerboseLogs || entry.EntryType.ToString() == "Warning" || entry.EntryType.ToString() == "Error")
                        {
                            var sentences = entry.Message.Split('.');

                            //Let's add the periods back.
                            for (var i = 0; i < sentences.Length; i++)
                            {
                                sentences[i] = string.Concat(sentences[i], ".");
                            }

                            EventLogObject obj = new EventLogObject()
                            {
                                Level = entry.EntryType.ToString(),
                                Summary = sentences[0],
                                Source = string.IsNullOrEmpty(entry.Source) ? null : entry.Source,
                                Timestamp = entry.TimeGenerated.ToString("o", CultureInfo.InvariantCulture),
                                Event = $"{entry.TimeGenerated.ToString("o", CultureInfo.InvariantCulture)} {entry.EntryType.ToString()} {entry.Message}"
                            };
                            obj.Data.Add(entry.Message);
                            results.Add(obj);
                        }
                    }
                }
                catch (Exception e)
                {
                    Log.Debug(e, "Error parsing log {0}", log.Source);
                }
            }

            foreach (var result in results) { yield return result; }
        }

        /// <summary>
        /// Parses /var/log/auth.log and /var/log/syslog (no way to distinguish severity)
        /// </summary>
        public IEnumerable<CollectObject> ExecuteLinux()
        {
            Regex LogHeader = new Regex("^([A-Z][a-z][a-z][0-9:\\s]*)?[\\s].*?[\\s](.*?): (.*)");
            var results = new List<CollectObject>();

            try
            {
                string[] authLog = File.ReadAllLines("/var/log/auth.log");
                foreach (var entry in authLog)
                {
                    // New log entries start with a timestamp like so:
                    // Sep  7 02:16:16 testbed sudo: pam_unix(sudo:session):session opened for user root
                    if (LogHeader.IsMatch(entry))
                    {
                        var obj = new EventLogObject()
                        {
                            Event = entry,
                            Summary = LogHeader.Matches(entry).Single().Groups[3].Captures[0].Value,
                            Timestamp = LogHeader.Matches(entry).Single().Groups[1].Captures[0].Value,
                            Source = "/var/log/auth.log",
                            Process = LogHeader.Matches(entry).Single().Groups[2].Captures[0].Value,
                        };

                        results.Add(obj);
                    }
                    // New log entries start with a timestamp like so:
                    // Sep  7 02:16:16 testbed systemd[1]: Reloading
                }
            }
            catch (Exception e) when (
                e is ArgumentException
                || e is ArgumentNullException
                || e is DirectoryNotFoundException
                || e is PathTooLongException
                || e is FileNotFoundException
                || e is IOException
                || e is NotSupportedException
                || e is System.Security.SecurityException
                || e is UnauthorizedAccessException)
            {
                Log.Debug("Failed to parse /var/auth/auth.log");
            }
            try
            {
                string[] sysLog = File.ReadAllLines("/var/log/syslog");
                foreach (var entry in sysLog)
                {
                    // New log entries start with a timestamp like so:
                    // Sep  7 02:16:16 testbed systemd[1]: Reloading
                    if (LogHeader.IsMatch(entry))
                    {
                        var obj = new EventLogObject()
                        {
                            Event = entry,
                            Summary = LogHeader.Matches(entry).Single().Groups[2].Captures[0].Value,
                            Timestamp = LogHeader.Matches(entry).Single().Groups[0].Captures[0].Value,
                            Source = "/var/log/syslog",
                            Process = LogHeader.Matches(entry).Single().Groups[1].Captures[0].Value,
                        };
                        results.Add(obj);
                    }
                }
            }
            catch (Exception e) when (
                e is ArgumentException
                || e is ArgumentNullException
                || e is DirectoryNotFoundException
                || e is PathTooLongException
                || e is FileNotFoundException
                || e is IOException
                || e is NotSupportedException
                || e is System.Security.SecurityException
                || e is UnauthorizedAccessException)
            {
                Log.Debug("Failed to parse /var/log/syslog");
            }

            foreach (var result in results) { yield return result; }
        }

        /// <summary>
        /// Collect event logs on macOS using the 'log' utility
        /// </summary>
        public IEnumerable<CollectObject> ExecuteMacOs()
        {

            var outputPath = Path.Combine(Directory.GetCurrentDirectory(), "events");
            var file = (GatherVerboseLogs) ? ExternalCommandRunner.RunExternalCommand("log", "show") : ExternalCommandRunner.RunExternalCommand("log", "show --predicate \"messageType == 16 || messageType == 17\"");

            // New log entries start with a timestamp like so:
            // 2019-09-25 20:38:53.784594-0700 0xdbf47    Error       0x0                  0      0    kernel: (Sandbox) Sandbox: mdworker(15726) deny(1) mach-lookup com.apple.security.syspolicy
            Regex LogHeader = new Regex("^([0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9] [0-2][0-9]:[0-5][0-9]:[0-5][0-9]).*?0x[0-9a-f]*[\\s]*([A-Za-z]*)[\\s]*0x[0-9a-f][\\s]*[0-9]*[\\s]*([0-9]*)[\\s]*(.*?):(.*)");


            List<string> data = null;
            string previousLine = null;
            foreach (var line in file.Split('\n'))
            {
                if (LogHeader.IsMatch(line))
                {
                    if (previousLine != null)
                    {
                        var obj = new EventLogObject()
                        {
                            Event = previousLine,
                            Level = LogHeader.Matches(previousLine).Single().Groups[2].Value,
                            Summary = $"{LogHeader.Matches(previousLine).Single().Groups[4].Captures[0].Value}:{LogHeader.Matches(previousLine).Single().Groups[5].Captures[0].Value}",
                            Timestamp = LogHeader.Matches(previousLine).Single().Groups[1].Captures[0].Value,
                            Source = LogHeader.Matches(previousLine).Single().Groups[4].Captures[0].Value
                        };
                        if (data.Count > 0)
                        {
                            obj.Data.AddRange(data);
                        }

                        yield return obj;
                    }
                    previousLine = line;
                    data = new List<string>();
                }
                else
                {
                    if (previousLine != null)
                    {
                        data.Add(line);
                    }
                }
            }
            if (previousLine != null)
            {
                var obj = new EventLogObject()
                {
                    Event = previousLine,
                    Level = LogHeader.Matches(previousLine).Single().Groups[2].Value,
                    Summary = $"{LogHeader.Matches(previousLine).Single().Groups[4].Captures[0].Value}:{LogHeader.Matches(previousLine).Single().Groups[5].Captures[0].Value}",
                    Timestamp = LogHeader.Matches(previousLine).Single().Groups[1].Captures[0].Value,
                    Source = LogHeader.Matches(previousLine).Single().Groups[4].Captures[0].Value
                };
                if (data.Count > 0)
                {
                    obj.Data.AddRange(data);
                }
                yield return obj;
            }
        }

        public override bool CanRunOnPlatform()
        {
            return RuntimeInformation.IsOSPlatform(OSPlatform.OSX) || RuntimeInformation.IsOSPlatform(OSPlatform.Windows) || RuntimeInformation.IsOSPlatform(OSPlatform.Linux);
        }
    }
}