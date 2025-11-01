using System;
using System.Collections.Generic;

namespace OhmGraphite
{
    /// <summary>
    /// Merges multiple IGiveSensors collectors into one stream.
    /// </summary>
    public class CompositeCollector : IGiveSensors
    {
        private readonly IGiveSensors[] _collectors;

        public CompositeCollector(params IGiveSensors[] collectors)
        {
            _collectors = collectors ?? Array.Empty<IGiveSensors>();
        }

        public IEnumerable<ReportedValue> ReadAllSensors()
        {
            foreach (var c in _collectors)
                foreach (var v in c.ReadAllSensors())
                    yield return v;
        }

        public void Start()
        {
            foreach (var c in _collectors)
                c.Start();
        }

        public void Dispose()
        {
            foreach (var c in _collectors)
                c.Dispose();
        }
    }
}