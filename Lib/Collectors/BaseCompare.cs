// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
using AttackSurfaceAnalyzer.Objects;
using AttackSurfaceAnalyzer.Types;
using AttackSurfaceAnalyzer.Utils;
using KellermanSoftware.CompareNetObjects;
using Newtonsoft.Json;
using Serilog;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.Linq;
using System.Reflection;
using System.Threading.Tasks;

namespace AttackSurfaceAnalyzer.Collectors
{
    /// <summary>
    /// The Generic Compare class.
    /// </summary>
    public class BaseCompare
    {
        public ConcurrentDictionary<string, ConcurrentQueue<CompareResult>> Results { get; }

        public BaseCompare()
        {
            Results = new ConcurrentDictionary<string, ConcurrentQueue<CompareResult>>();
            foreach (RESULT_TYPE result_type in Enum.GetValues(typeof(RESULT_TYPE)))
            {
                foreach (CHANGE_TYPE change_type in Enum.GetValues(typeof(CHANGE_TYPE)))
                {
                    Results[$"{result_type.ToString()}_{change_type.ToString()}"] = new ConcurrentQueue<CompareResult>();
                }
            }
        }

        /// <summary>
        /// Deserialize a Collect object from a RawCollectResult
        /// </summary>
        /// <param name="res">The RawCollectResult containing the JsonSerialized object to hydrate.</param>
        /// <returns>An appropriately typed collect object based on the collect result passed in, or null if the RESULT_TYPE is unknown.</returns>
        public static CollectObject Hydrate(RawCollectResult res)
        {
            if (res == null)
            {
                throw new NullReferenceException();
            }
            switch (res.ResultType)
            {
                case RESULT_TYPE.CERTIFICATE:
                    return JsonConvert.DeserializeObject<CertificateObject>(res.Serialized);
                case RESULT_TYPE.FILE:
                    return JsonConvert.DeserializeObject<FileSystemObject>(res.Serialized);
                case RESULT_TYPE.PORT:
                    return JsonConvert.DeserializeObject<OpenPortObject>(res.Serialized);
                case RESULT_TYPE.REGISTRY:
                    return JsonConvert.DeserializeObject<RegistryObject>(res.Serialized);
                case RESULT_TYPE.SERVICE:
                    return JsonConvert.DeserializeObject<ServiceObject>(res.Serialized);
                case RESULT_TYPE.USER:
                    return JsonConvert.DeserializeObject<UserAccountObject>(res.Serialized);
                case RESULT_TYPE.GROUP:
                    return JsonConvert.DeserializeObject<GroupAccountObject>(res.Serialized);
                case RESULT_TYPE.FIREWALL:
                    return JsonConvert.DeserializeObject<FirewallObject>(res.Serialized);
                case RESULT_TYPE.COM:
                    return JsonConvert.DeserializeObject<ComObject>(res.Serialized);
                case RESULT_TYPE.LOG:
                    return JsonConvert.DeserializeObject<EventLogObject>(res.Serialized);
                default:
                    return null;
            }
        }


        /// <summary>
        /// Compares all the common collectors between two runs.
        /// </summary>
        /// <param name="firstRunId">The Base run id.</param>
        /// <param name="secondRunId">The Compare run id.</param>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Collecting telemetry on exceptions.")]
        public void Compare(string firstRunId, string secondRunId)
        {

            if (firstRunId == null)
            {
                throw new ArgumentNullException(nameof(firstRunId));
            }
            if (secondRunId == null)
            {
                throw new ArgumentNullException(nameof(secondRunId));
            }

            DatabaseManager.db.BeginTrans();

            var StopWatch = System.Diagnostics.Stopwatch.StartNew();

            var SubWatch = System.Diagnostics.Stopwatch.StartNew();

            var addObjects = DatabaseManager.GetMissingFromFirst(firstRunId, secondRunId);

            SubWatch.Stop();
            var t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            var answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed Calculated Added Objects in {0}", answer);
            SubWatch = System.Diagnostics.Stopwatch.StartNew();

            var removeObjects = DatabaseManager.GetMissingFromFirst(secondRunId, firstRunId);

            SubWatch.Stop();
            t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed Calculated Removed Objects in {0}", answer);
            SubWatch = System.Diagnostics.Stopwatch.StartNew();

            var modifyObjects = DatabaseManager.GetModified(firstRunId, secondRunId);

            SubWatch.Stop();
            t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed Calculated Modified Objects in {0}", answer);
            SubWatch = System.Diagnostics.Stopwatch.StartNew();

            Parallel.ForEach(addObjects,
                            (added =>
            {
                var obj = new CompareResult()
                {
                    Compare = added.ColObj,
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                    CompareRowKey = added.InstanceHash,
                    ChangeType = CHANGE_TYPE.CREATED,
                    ResultType = added.ColObj.ResultType,
                    Identity = added.ColObj.Identity
                };
                Log.Debug($"Adding {obj.Identity}");
                Results[$"{added.ColObj.ResultType.ToString()}_{CHANGE_TYPE.CREATED.ToString()}"].Enqueue(obj);
            }));

            SubWatch.Stop();
            t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed Parsed Added Objects in {0}", answer);
            SubWatch = System.Diagnostics.Stopwatch.StartNew();


            Parallel.ForEach(removeObjects,
                            (removed =>
            {
                var obj = new CompareResult()
                {
                    Base = removed.ColObj,
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                    BaseRowKey = removed.InstanceHash,
                    ChangeType = CHANGE_TYPE.DELETED,
                    ResultType = removed.ColObj.ResultType,
                    Identity = removed.ColObj.Identity
                };

                Results[$"{removed.ColObj.ResultType.ToString()}_{CHANGE_TYPE.DELETED.ToString()}"].Enqueue(obj);
            }));

            SubWatch.Stop();
            t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed Parsed Removed Objects in {0}", answer);
            SubWatch = System.Diagnostics.Stopwatch.StartNew();


            Parallel.ForEach(modifyObjects,
                            (modified =>
            {
                var first = modified.Item1;
                var second = modified.Item2;
                var obj = new CompareResult()
                {
                    Base = first.ColObj,
                    Compare = second.ColObj,
                    BaseRunId = firstRunId,
                    CompareRunId = secondRunId,
                    BaseRowKey = modified.Item1.InstanceHash,
                    CompareRowKey = modified.Item2.InstanceHash,
                    ChangeType = CHANGE_TYPE.MODIFIED,
                    ResultType = modified.Item1.ColObj.ResultType,
                    Identity = modified.Item1.ColObj.Identity
                };

                var firstProperties = first.ColObj.GetType().GetProperties();

                var firstDict = new Dictionary<string, object>();
                var secondDict = new Dictionary<string, object>();

                foreach (var prop in firstProperties)
                {
                    try
                    {
                        object propVal = prop.GetValue(first.ColObj);
                        firstDict.Add(prop.Name, propVal);
                    }
                    catch (Exception e)
                    {
                        Log.Debug(e, "Generic exception. Tell a programmer.");
                        Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                        ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                        AsaTelemetry.TrackEvent("CompareException", ExceptionEvent);
                    }
                }

                var secondProperties = second.ColObj.GetType().GetProperties();

                foreach (var prop in secondProperties)
                {
                    try
                    {
                        object propVal = prop.GetValue(second.ColObj);
                        secondDict.Add(prop.Name, propVal);
                    }
                    catch (Exception e)
                    {
                        Log.Debug(e, "Generic exception. Tell a programmer.");
                        Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                        ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                        AsaTelemetry.TrackEvent("CompareException", ExceptionEvent);
                    }
                }

                // These are potentially modified
                foreach (var propertyName in secondDict.Keys.Intersect(firstDict.Keys))
                {
                    obj.Diffs.AddRange(GenerateDiffs(propertyName, firstDict[propertyName], secondDict[propertyName]));
                }

                // These are added
                foreach (var propertyName in secondDict.Keys.Except(firstDict.Keys))
                {
                    obj.Diffs.AddRange(GenerateDiffs(propertyName, null, secondDict[propertyName]));
                }

                // These are removed
                foreach (var propertyName in firstDict.Keys.Except(secondDict.Keys))
                {
                   obj.Diffs.AddRange(GenerateDiffs(propertyName, firstDict[propertyName], null));
                }

                Results[$"{modified.Item1.ColObj.ResultType.ToString()}_{CHANGE_TYPE.MODIFIED.ToString()}"].Enqueue(obj);
            }));

            SubWatch.Stop();
            t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed Parsed Modified Objects in {0}", answer);
            SubWatch = System.Diagnostics.Stopwatch.StartNew();


            foreach (var empty in Results.Where(x => x.Value.Count == 0))
            {
                Results.Remove(empty.Key, out _);
            }

            StopWatch.Stop();
            t = TimeSpan.FromMilliseconds(StopWatch.ElapsedMilliseconds);
            answer = string.Format(CultureInfo.InvariantCulture, "{0:D2}h:{1:D2}m:{2:D2}s:{3:D3}ms",
                                    t.Hours,
                                    t.Minutes,
                                    t.Seconds,
                                    t.Milliseconds);
            Log.Debug("Completed comparing in {0}", answer);
        }

        public static List<Diff> GenerateDiffs(string propName, object value1, object value2)
        {
            var compareLogic = new CompareLogic();
            compareLogic.Config.IgnoreCollectionOrder = true;
            List<Diff> diffs = new List<Diff>();

            try
            {
                object added = null;
                object removed = null;
                object changed = new object();

                object firstProp = value1;
                object secondProp = value2;
                if (firstProp == null && secondProp == null)
                {
                    return diffs;
                }
                else if (firstProp == null && secondProp != null)
                {
                    added = value2;
                    diffs = GetDiffs(propName, added, null);
                }
                else if (secondProp == null && firstProp != null)
                {
                    removed = value1;
                    diffs = GetDiffs(propName, null, removed);
                }
                else if (firstProp != null && secondProp != null && compareLogic.Compare(firstProp, secondProp).AreEqual)
                {
                    return diffs;
                }
                else
                {
                    if (firstProp is List<string>)
                    {
                        added = ((List<string>)firstProp).Except((List<string>)secondProp);
                        removed = ((List<string>)firstProp).Except((List<string>)secondProp);
                        if (!((IEnumerable<string>)added).Any())
                        {
                            added = null;
                        }
                        if (!((IEnumerable<string>)removed).Any())
                        {
                            removed = null;
                        }
                    }
                    else if (firstProp is List<KeyValuePair<string, string>>)
                    {
                        added = ((List<KeyValuePair<string, string>>)secondProp).Except((List<KeyValuePair<string, string>>)firstProp);
                        removed = ((List<KeyValuePair<string, string>>)firstProp).Except((List<KeyValuePair<string, string>>)secondProp);
                        if (!((IEnumerable<KeyValuePair<string, string>>)added).Any())
                        {
                            added = null;
                        }
                        if (!((IEnumerable<KeyValuePair<string, string>>)removed).Any())
                        {
                            removed = null;
                        }
                    }
                    else if (firstProp is Dictionary<string, string>)
                    {
                        added = ((Dictionary<string, string>)secondProp)
                            .Except((Dictionary<string, string>)firstProp)
                            .ToDictionary(x => x.Key, x => x.Value);

                        removed = ((Dictionary<string, string>)firstProp)
                            .Except((Dictionary<string, string>)secondProp)
                            .ToDictionary(x => x.Key, x => x.Value);
                        if (!((IEnumerable<KeyValuePair<string, string>>)added).Any())
                        {
                            added = null;
                        }
                        if (!((IEnumerable<KeyValuePair<string, string>>)removed).Any())
                        {
                            removed = null;
                        }
                    }
                    else if (firstProp is string || firstProp is int || firstProp is bool)
                    {
                        diffs.Add(new Diff() { Field = propName, Before = firstProp, After = secondProp });
                    }
                    else
                    {
                        diffs.Add(new Diff() { Field = propName, Before = firstProp, After = secondProp });
                    }
                }

                var addedAndRemoved = GetDiffs(propName, added, removed);
                diffs.AddRange(addedAndRemoved);
            }
            catch (InvalidCastException e)
            {
                Log.Debug(e, $"Failed to cast {JsonConvert.SerializeObject(propName)}");
            }
            catch (Exception e)
            {
                Log.Debug(e, "Generic exception. Tell a programmer.");
                Dictionary<string, string> ExceptionEvent = new Dictionary<string, string>();
                ExceptionEvent.Add("Exception Type", e.GetType().ToString());
                AsaTelemetry.TrackEvent("CompareException", ExceptionEvent);
            }
            return diffs;
        }

        /// <summary>
        /// Creates a list of Diff objects based on an object property and findings.
        /// </summary>
        /// <param name="prop">The property of the referenced object.</param>
        /// <param name="added">The added findings.</param>
        /// <param name="removed">The removed findings.</param>
        /// <returns></returns>
        public static List<Diff> GetDiffs(string prop, object added, object removed)
        {
            List<Diff> diffsOut = new List<Diff>();
            if (added != null && prop != null)
            {
                diffsOut.Add(new Diff()
                {
                    Field = prop,
                    After = added
                });
            }
            if (removed != null && prop != null)
            {
                diffsOut.Add(new Diff()
                {
                    Field = prop,
                    Before = removed
                });
            }
            return diffsOut;
        }

        /// <summary>
        /// Compare but with a Try/Catch block for exceptions.
        /// </summary>
        /// <param name="firstRunId">The Base run id.</param>
        /// <param name="secondRunId">The Compare run id.</param>
        /// <returns></returns>
        public bool TryCompare(string firstRunId, string secondRunId)
        {
            Start();
            Compare(firstRunId, secondRunId);
            Stop();
            return true;
        }

        private RUN_STATUS _running = RUN_STATUS.NOT_STARTED;

        /// <summary>
        /// Returns if the comparators are still running.
        /// </summary>
        /// <returns>RUN_STATUS indicating run status.</returns>
        public RUN_STATUS IsRunning()
        {
            return _running;
        }

        /// <summary>
        /// Set status to running.
        /// </summary>
        public void Start()
        {
            _running = RUN_STATUS.RUNNING;

        }

        /// <summary>
        /// Sets status to completed.
        /// </summary>
        public void Stop()
        {
            _running = RUN_STATUS.COMPLETED;
        }

    }
}