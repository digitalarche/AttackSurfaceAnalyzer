// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using Serilog;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Threading;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// Base class for all collectors.
    /// </summary>
    public abstract class BaseCollector : IPlatformRunnable
    {
        public string RunId { get; set; }

        private RUN_STATUS _running = RUN_STATUS.NOT_STARTED;

        private int _numCollected = 0;

        private Stopwatch watch;

        public void Execute()
        {
            if (!CanRunOnPlatform())
            {
                Log.Warning(string.Format(CultureInfo.InvariantCulture, Strings.Get("Err_PlatIncompat"), GetType().ToString()));
                return;
            }
            Start();

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            ExecuteInternal();

            stopwatch.Stop();
            TimeSpan t = TimeSpan.FromMilliseconds(stopwatch.ElapsedMilliseconds);
            string answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);

            Log.Debug("Completed Gathering in {0}", answer);

            stopwatch = System.Diagnostics.Stopwatch.StartNew();

            var StartingCount = DatabaseManager.WriteQueue.Count;
            Log.Debug("Begining flush of {0} results.", StartingCount);

            while (DatabaseManager.WriteQueue.Count > 0)
            {
                Thread.Sleep(100);
            }

            stopwatch.Stop();
            t = TimeSpan.FromMilliseconds(stopwatch.ElapsedMilliseconds);
            answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed flushing in {0} ({1}/s)", answer, (((double)StartingCount) / stopwatch.ElapsedMilliseconds) * 1000);

            Stop();
        }

        public abstract bool CanRunOnPlatform();

        public abstract void ExecuteInternal();


        public RUN_STATUS IsRunning()
        {
            return _running;
        }

        public void Start()
        {
            _running = RUN_STATUS.RUNNING;
            watch = System.Diagnostics.Stopwatch.StartNew();

            Log.Information(Strings.Get("Starting"), this.GetType().Name);
        }

        public void Stop()
        {
            _running = RUN_STATUS.COMPLETED;
            watch.Stop();
            TimeSpan t = TimeSpan.FromMilliseconds(watch.ElapsedMilliseconds);
            string answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Information(Strings.Get("Completed"), this.GetType().Name, answer);
            var EndEvent = new Dictionary<string, string>();
            EndEvent.Add("Scanner", this.GetType().Name);
            EndEvent.Add("Duration", watch.ElapsedMilliseconds.ToString(CultureInfo.InvariantCulture));
            EndEvent.Add("NumResults", _numCollected.ToString(CultureInfo.InvariantCulture));
            AsaTelemetry.TrackEvent("EndScanFunction", EndEvent);
        }

        public int NumCollected()
        {
            return _numCollected;
        }
    }
}